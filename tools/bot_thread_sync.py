"""Fail-closed thread synchronization.

Outbound owns only the sender projection and transport; inbound owns only the recipient
projection, receipt and processing admission, under an independently authenticated
recipient owner.  Authority (profile, tenant, owner, lease) comes exclusively from a
runner-issued ``GatewayAuthContext``; envelopes, profile names, env and chat text are
assertions that must agree with it, never sources of it.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets as _secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Callable, Iterable

from tools import pinned_fs

MAX_ATTEMPTS = 8
TTL_SECONDS = 24 * 60 * 60
BACKOFF_CAP_SECONDS = 300
CLAIM_LEASE_SECONDS = 120
COMPLETION_LEASE_SECONDS = 900  # how long a SCHEDULED model run is trusted before it may be re-driven
MAX_AUTH_LEASE_SECONDS = 900
SCANNER_VERSION = "local-v3"
MASK = "[MASKED]"

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){3,7}(?:[ -]?[A-Z0-9]{1,3})?\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("api_key", re.compile(r"(?i)\b(?:sk|pk)_[a-z0-9_-]{16,}\b")),
    ("credential", re.compile(
        r"(?i)(\b(?:token|password|passwd|passwort|kennwort|api[_ -]?key|secret)\s*[:=]\s*)[^\s,;]+")),
    ("pin", re.compile(r"(?i)(\b(?:cvc|cvv|pin|2fa|otp|tan|verification(?: code)?)\s*[:=]?\s*)\d{3,8}\b")),
    ("document", re.compile(r"(?i)\b(?:passport|document|id|ausweis)[ _-]?(?:no|number|nr)?\s*[:=]\s*[A-Z0-9-]{6,}\b")),
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]+$")

# --------------------------------------------------------------------------- masking


@dataclass(frozen=True)
class MaskedText:
    text: str
    match_count: int
    provenance: str
    scanner_version: str = SCANNER_VERSION
    classes: tuple[str, ...] = ()
    spans: tuple[tuple[int, int], ...] = ()
    digest: str = ""

    def proof(self) -> dict[str, Any]:
        return {"provenance": self.provenance, "scanner_version": self.scanner_version,
                "match_count": self.match_count, "classes": list(self.classes),
                "spans": [list(span) for span in self.spans], "digest": self.digest}


def _spans(text: str) -> tuple[tuple[int, int], ...]:
    return tuple((m.start(), m.end()) for m in re.finditer(re.escape(MASK), text))


def mask_text(text: str, *, secrets: Iterable[str] = ()) -> MaskedText:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    out, matches, classes = text, 0, set()
    values = sorted({v for v in secrets if isinstance(v, str) and len(v) >= 3}, key=len, reverse=True)
    for value in values:
        count = out.count(value)
        if count:
            out = out.replace(value, MASK)
            matches += count
            classes.add("profile_secret")
    for label, pattern in _SECRET_PATTERNS:
        changed = 0

        def replace(match, _label=label):
            nonlocal changed
            if match.group(0).endswith(MASK):
                return match.group(0)
            changed += 1
            return (match.group(1) if match.lastindex else "") + MASK
        out = pattern.sub(replace, out)
        if changed:
            matches += changed
            classes.add(label)
    if any(value in out for value in values):  # a surviving secret makes the scan untrustworthy
        raise ValueError("masking_unproven")
    return MaskedText(out, matches, f"scan:{SCANNER_VERSION};matches={matches}",
                      classes=tuple(sorted(classes)), spans=_spans(out),
                      digest=hashlib.sha256(out.encode("utf-8")).hexdigest())


PROOF_KEYS = frozenset({"provenance", "scanner_version", "match_count", "classes", "spans", "digest"})
PROOF_CLASSES = frozenset({"private_key", "iban", "card", "api_key", "credential", "pin", "document",
                           "profile_secret"})
MAX_PROOF_SPANS = 1024
MAX_PROOF_MATCHES = 4096
MAX_TEXT_CHARS = 131072  # hard cap on masked message text (and therefore on every proof coordinate)


def canonical_masking_proof(proof: Any) -> dict[str, Any] | None:
    """Exact, closed schema for a masking proof. Returns a canonical dict REBUILT from validated typed
    values (never the caller's object), or None. No free-form strings: provenance is derived, classes are
    enumerated, spans are bounded ordered int pairs, the digest is 64 lowercase hex."""
    if not isinstance(proof, dict) or set(proof) != PROOF_KEYS:
        return None
    count, classes, spans = proof["match_count"], proof["classes"], proof["spans"]
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= MAX_PROOF_MATCHES:
        return None
    if proof["scanner_version"] != SCANNER_VERSION or proof["provenance"] != f"scan:{SCANNER_VERSION};matches={count}":
        return None
    if not isinstance(classes, list) or len(classes) > len(PROOF_CLASSES) \
            or any(not isinstance(c, str) or c not in PROOF_CLASSES for c in classes) \
            or classes != sorted(set(classes)):
        return None
    if not isinstance(spans, list) or len(spans) > MAX_PROOF_SPANS:
        return None
    previous_end = 0
    clean: list[list[int]] = []
    for span in spans:
        if not (isinstance(span, (list, tuple)) and len(span) == 2
                and all(isinstance(v, int) and not isinstance(v, bool) for v in span)):
            return None
        start, end = span
        # ints only (checked above); compared BEFORE any arithmetic/string work so 10**1000 costs nothing
        if not (0 <= start < end <= MAX_TEXT_CHARS) or start < previous_end or end - start != len(MASK):
            return None
        previous_end = end
        clean.append([start, end])
    digest = proof["digest"]
    if not (isinstance(digest, str) and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)):
        return None
    return {"provenance": f"scan:{SCANNER_VERSION};matches={count}", "scanner_version": SCANNER_VERSION,
            "match_count": count, "classes": list(classes), "spans": clean, "digest": digest}


def verify_masking_proof(text: str, proof: Any, *, secrets: Iterable[str] = ()) -> bool:
    """Receiver-side: proof must describe exactly this text and a fresh scan must find nothing new."""
    proof = canonical_masking_proof(proof)
    if proof is None or len(text) > MAX_TEXT_CHARS or any(end > len(text) for _, end in proof["spans"]):
        return False
    if proof.get("digest") != hashlib.sha256(text.encode("utf-8")).hexdigest():
        return False
    if [list(s) for s in _spans(text)] != [list(s) for s in proof.get("spans", [])]:
        return False
    if not isinstance(proof.get("classes"), list) or not isinstance(proof.get("match_count"), int):
        return False
    try:
        return mask_text(text, secrets=secrets).match_count == 0
    except ValueError:
        return False


def profile_secret_values(profile_home: str | Path) -> tuple[str, ...]:
    """Values of the profile's own secret scope; never logged or returned in output."""
    from agent.secret_scope import build_profile_secret_scope
    try:
        scope = build_profile_secret_scope(Path(profile_home))
    except Exception:
        raise ValueError("secrets_unavailable")
    return tuple(v for v in scope.values() if isinstance(v, str) and len(v) >= 3)


# --------------------------------------------------------------------------- authority


def _segment(value: str, label: str) -> str:
    value = str(value or "")
    if not value or "/" in value or "\\" in value or "." in value or not _SAFE_ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _thread(value: dict[str, Any] | None, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or str(value.get("platform", "")).lower() != "telegram":
        raise ValueError(f"{label} must be an active Telegram thread")
    if set(value) != {"platform", "chat_id", "thread_id"} \
            or any(not isinstance(v, str) or len(v) > 256 for v in value.values()):
        raise ValueError(f"{label} has unknown or non-string fields")  # schema-closed, bounded
    result = {key: str(value.get(key) or "") for key in ("platform", "chat_id", "thread_id")}
    if not result["chat_id"] or not result["thread_id"] or result["thread_id"].lower().startswith("bot"):
        raise ValueError(f"{label} must identify an active Telegram thread")
    return result


def _norm(thread: dict[str, Any]) -> dict[str, str]:
    return {key: str((thread or {}).get(key) or "") for key in ("platform", "chat_id", "thread_id")}


RUNTIME_INSTANCE = uuid.uuid4().hex  # non-secret process identity; authority lives in tools.bot_thread_authority
_uuid7_lock = threading.Lock()
_uuid7_last_ms = -1
_uuid7_last_random = -1


def new_message_id() -> str:
    """Return a monotonic RFC 9562 UUIDv7 for a sender-owned message envelope."""
    global _uuid7_last_ms, _uuid7_last_random
    with _uuid7_lock:
        milliseconds = time.time_ns() // 1_000_000
        if milliseconds < _uuid7_last_ms:
            milliseconds = _uuid7_last_ms
        random_bits = _secrets.randbits(74)
        if milliseconds == _uuid7_last_ms and random_bits <= _uuid7_last_random:
            random_bits = _uuid7_last_random + 1
        if random_bits >= (1 << 74):
            milliseconds += 1
            random_bits = _secrets.randbits(74)
        _uuid7_last_ms, _uuid7_last_random = milliseconds, random_bits
    value = ((milliseconds & ((1 << 48) - 1)) << 80) | (7 << 76)
    value |= ((random_bits >> 62) & 0xFFF) << 64
    value |= 0x8000000000000000 | (random_bits & ((1 << 62) - 1))
    return str(uuid.UUID(int=value))


def _valid_message_id(value: Any) -> bool:
    try:
        parsed = uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError):
        return False
    return parsed.version == 7 and parsed.variant == uuid.RFC_4122 and str(parsed) == str(value)


@dataclass(frozen=True)
class GatewayAuthContext:
    """Authenticated context DATA. It confers no authority: only a live RunnerGrant bound to it does."""
    profile_home: str
    profile: str
    owner: str
    tenant: str
    conversation_id: str
    thread: dict[str, Any]
    live_session_id: str
    runtime_instance: str
    owner_token: str
    turn_id: str
    observed_at: float
    lease_expires_at: float

    def invalid(self, now: float) -> str | None:
        if not isinstance(self.tenant, str) or not self.tenant.strip():
            return "tenant_unbekannt"
        if self.owner != "max" or not self.profile or not self.profile_home:
            return "owner_mehrdeutig"
        if not (isinstance(self.observed_at, (int, float)) and isinstance(self.lease_expires_at, (int, float))
                and math.isfinite(self.observed_at) and math.isfinite(self.lease_expires_at)):
            return "owner_veraltet"
        if self.observed_at > now + 5 or self.lease_expires_at <= now:
            return "owner_veraltet"
        if self.lease_expires_at - self.observed_at > MAX_AUTH_LEASE_SECONDS:
            return "owner_veraltet"
        if self.runtime_instance != RUNTIME_INSTANCE:
            return "owner_abweichend"  # data-level check only; AUTHORITY is the opaque RunnerGrant
        return None


@dataclass(frozen=True)
class Owner:
    profile_home: str
    profile: str
    platform: str
    chat_id: str
    thread_id: str
    lease_id: str
    live_session_id: str
    lease_expires_at: float
    participant_ids: tuple[str, ...] = ("max",)

    def valid(self, now: float) -> str | None:
        if self.platform != "telegram" or not self.chat_id or not self.thread_id:
            return "owner_mehrdeutig"
        if self.participant_ids != ("max",):
            return "owner_mehrdeutig"
        if not isinstance(self.lease_expires_at, (int, float)) or not math.isfinite(self.lease_expires_at):
            return "owner_veraltet"
        if self.lease_expires_at <= now:
            return "owner_veraltet"
        return None


# --------------------------------------------------------------------------- envelope


_PAYLOAD_ONLY_KEYS = frozenset({"egress_key", "sender_projection_id"})  # machine-payload extras, never persisted
_LEGACY_TENANT_SOURCES = {"gateway_context": "kontext"}
_ALTNAMEN = {"outbound_done": "bestaetigt"}


def _ist(row: dict[str, Any], *kinds: str) -> bool:
    """Read queue history through the contract names, including durable legacy rows."""
    kind = str(row.get("kind") or "")
    if kind == "queue":
        kind = "versuch" if int(row.get("attempts", 0)) > 0 else "eingereiht"
    kind = _ALTNAMEN.get(kind, kind)
    return kind in kinds


def _tenant_source_equivalent(source: str | None) -> str | None:
    """Read the former source label as its contract successor without rewriting storage."""
    return _LEGACY_TENANT_SOURCES.get(source, source)


@dataclass(frozen=True)
class ThreadEnvelope:
    conversation_id: str
    message_id: str
    parent_message_id: str | None
    sender: str
    recipient: str
    tenant: str | None
    tenant_source: str | None
    source_thread: dict[str, Any]
    target_thread: dict[str, Any]
    text: str
    transport: str
    art: str = "gespraech"
    projection_requested: bool = False
    is_root: bool | None = None
    status: str = "eingereiht"
    spiegel: bool = False
    masking: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _segment(self.conversation_id, "conversation_id")
        _segment(self.message_id, "message_id")
        if not self.sender or not self.recipient:
            raise ValueError("sender and recipient are required")
        if self.parent_message_id is not None:
            _segment(self.parent_message_id, "parent_message_id")
        if self.parent_message_id == self.message_id:
            raise ValueError("parent_message_id cannot equal message_id")
        if self.is_root is True and self.parent_message_id is not None:
            raise ValueError("root message cannot have a parent")
        if self.is_root is False and not self.parent_message_id:
            raise ValueError("follow-up message requires parent_message_id")
        object.__setattr__(self, "source_thread", _thread(self.source_thread, "source_thread"))
        object.__setattr__(self, "target_thread", _thread(self.target_thread, "target_thread"))
        if not isinstance(self.text, str) or len(self.text) > MAX_TEXT_CHARS:
            raise ValueError("text too large")
        if self.art not in {"gespraech", "arbeitsauftrag"}:
            raise ValueError("invalid art")
        if not isinstance(self.spiegel, bool):
            raise ValueError("spiegel must be boolean")
        if self.tenant is not None and not self.tenant_source:
            raise ValueError("tenant_source is required with tenant")
        if self.masking:  # schema-close at EVERY construction (wire, payload, storage): canonical or rejected
            canonical = canonical_masking_proof(self.masking)
            if canonical is None:
                raise ValueError("masking_proof_ungueltig")
            object.__setattr__(self, "masking", canonical)

    def key(self, target: str = "target") -> tuple[str, str, str]:
        thread = self.target_thread if target == "target" else self.source_thread
        return self.conversation_id, self.message_id, f"{thread['chat_id']}:{thread['thread_id']}"

    @property
    def digest(self) -> str:
        body = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    @property
    def replay_digest(self) -> str:
        """Digest for replay comparison; legacy source spelling is semantically identical."""
        body = asdict(self)
        body["tenant_source"] = _tenant_source_equivalent(self.tenant_source)
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def to_wire(self) -> dict[str, Any]:
        """Complete envelope plus its integrity digest; the only A2A/native transport form."""
        return {**asdict(self), "envelope_digest": self.digest}

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ThreadEnvelope":
        """Rebuild the canonical (queued-status) envelope from a machine payload."""
        names = {f.name for f in fields(cls)}
        extra = set(payload) - names - _PAYLOAD_ONLY_KEYS
        if extra:  # exactly as strict as from_wire: unknown fields fail before any persistence
            raise ValueError("unknown payload fields")
        return cls(**{**{k: v for k, v in payload.items() if k in names}, "status": "eingereiht"})

    @classmethod
    def from_wire(cls, data: Any) -> "ThreadEnvelope":
        if not isinstance(data, dict):
            raise ValueError("envelope must be an object")
        names = {f.name for f in fields(cls)}
        extra = set(data) - names - {"envelope_digest"}
        if extra:
            raise ValueError("unknown envelope fields")
        envelope = cls(**{k: data[k] for k in names if k in data})
        if not hmac.compare_digest(str(data.get("envelope_digest") or ""), envelope.digest):
            raise ValueError("envelope digest mismatch")
        return envelope


@dataclass(frozen=True)
class SyncResult:
    status: str
    reason: str = ""
    attempts: int = 0
    message_id: str = ""
    ticket: Any = None  # dispatch ticket for externally dispatched inbound ("admitted")


# --------------------------------------------------------------------------- evidence

SEAMS: dict[str, tuple[str, str]] = {
    "message_agent": ("tools/bot_mode_dm.py", "def message_agent_tool"),
    "provider_binding": ("tools/bot_thread_provider.py", "def build_thread_sync"),
    "tenant": ("gateway/run_thread_context.py", "def build_thread_auth_context"),
    "a2a_admission": ("plugins/platforms/a2a/adapter.py", "def _receive_thread_sync"),
    "a2a_ids": ("plugins/platforms/a2a/tools.py", "def _send_task"),
    "a2a_ablage": ("plugins/platforms/a2a/protocol.py", "def persist_message"),
    "owner_lease": ("tools/bot_thread_provider.py", "def _active_owner"),
    "egress": ("tools/bot_thread_provider.py", "def _project"),
    "pre_session_hook": ("tools/bot_thread_provider.py", "def _pre_session_hook"),
    "sender_edit": ("tools/bot_thread_provider.py", "def _edit_projection"),
    "audit": ("tools/bot_thread_sync.py", "def _audit"),
}


def build_evidence_entries(repo_root: str | Path, revision: str) -> dict[str, dict[str, Any]]:
    root = Path(repo_root)
    entries: dict[str, dict[str, Any]] = {}
    for name, (rel, seam) in SEAMS.items():
        data = (root / rel).read_bytes()
        lines = data.decode("utf-8").splitlines()
        line = next(i for i, text in enumerate(lines, 1) if seam in text)
        entries[name] = {"proven": True, "revision": revision, "kind": "Code", "location": f"{rel}:{line}",
                         "file": rel, "line": line, "seam": seam, "sha256": hashlib.sha256(data).hexdigest()}
    return entries


class EvidenceRegistry:
    """Static seam location + runtime attestation bound to the current instance/owner/turn.

    A name is proven only when (a) its entry matches revision, file hash, line and seam in this
    checkout and (b) the seam attested itself under the *currently bound* runtime identity.
    """

    def __init__(self, revision: str, entries: dict[str, dict[str, Any]] | None = None,
                 *, repo_root: str | Path | None = None):
        self.revision = revision
        self.entries = entries or {}
        self.repo_root = Path(repo_root) if repo_root else None
        self._bound: tuple[str, str, str] | None = None
        self._attested: dict[str, tuple[tuple[str, str, str], str, int, str]] = {}
        self._lock = threading.Lock()

    def bind(self, *, instance: str, owner_token: str, turn: str) -> None:
        with self._lock:
            bound = (instance, owner_token, turn)
            if bound != self._bound:
                self._bound, self._attested = bound, {}

    def _static(self, name: str) -> tuple[str, int] | None:
        item = self.entries.get(name) or {}
        if not (item.get("proven") is True and item.get("revision") == self.revision
                and item.get("kind") == "Code" and item.get("file") and item.get("sha256")
                and isinstance(item.get("line"), int) and item.get("seam") and self.repo_root):
            return None
        try:
            data = (self.repo_root / str(item["file"])).read_bytes()
            line = data.decode("utf-8").splitlines()[item["line"] - 1]
        except (OSError, IndexError, UnicodeDecodeError):
            return None
        if hashlib.sha256(data).hexdigest() != item["sha256"] or item["seam"] not in line:
            return None
        return item["sha256"], item["line"]

    def attest(self, name: str) -> bool:
        static = self._static(name)
        with self._lock:
            if static is None or self._bound is None:
                return False
            self._attested[name] = (self._bound, static[0], static[1], self.revision)
            return True

    def proven(self, name: str) -> bool:
        static = self._static(name)
        with self._lock:
            att = self._attested.get(name)
            return bool(static and att and self._bound and att == (self._bound, static[0], static[1], self.revision))

    def require(self, *names: str) -> str | None:
        return next((name for name in names if not self.proven(name)), None)


def artifact_revision(root: str | Path) -> str:
    """Stable build identity: digest of the exact seam files. Independent of any VCS commit, so
    committing or packaging the identical artifact never invalidates the shipped registry."""
    digest = hashlib.sha256()
    for name, (rel, seam) in sorted(SEAMS.items()):
        digest.update(f"{name}|{rel}|{seam}|".encode())
        digest.update(hashlib.sha256((Path(root) / rel).read_bytes()).digest())
    return "artifact:" + digest.hexdigest()


def load_evidence_registry(path: str | Path | None = None) -> EvidenceRegistry:
    """Shipped registry; malformed or stale (different artifact) evidence is explicitly unproven."""
    source = Path(path) if path is not None else Path(__file__).with_name("bot_thread_evidence.json")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 2 or not isinstance(raw.get("revision"), str) \
                or not isinstance(raw.get("entries"), dict):
            raise ValueError("invalid evidence registry")
        root = source.parent.parent
        if artifact_revision(root) != raw["revision"]:
            return EvidenceRegistry("stale", raw["entries"], repo_root=root)
        return EvidenceRegistry(raw["revision"], raw["entries"], repo_root=root)
    except Exception:
        return EvidenceRegistry("unproven", {})


def write_evidence_registry(path: str | Path | None = None) -> Path:
    root = Path(__file__).resolve().parent.parent
    revision = artifact_revision(root)
    target = Path(path) if path is not None else Path(__file__).with_name("bot_thread_evidence.json")
    target.write_text(json.dumps({"schema_version": 2, "revision": revision,
                                  "entries": build_evidence_entries(root, revision)}, indent=2) + "\n")
    return target


# --------------------------------------------------------------------------- journal


class AuthorityLost(RuntimeError):
    """The grant was revoked/expired/deactivated: the operation stops with zero further mutation."""


class Journal:
    """Own-home append-only journal; every open is pinned via dir_fd + O_NOFOLLOW."""

    def __init__(self, root: str | Path, *, trusted_base: str | Path | None = None):
        self.root = Path(root)
        base = Path(trusted_base) if trusted_base is not None else self.root.parent
        self._base = base
        self._parts = self.root.relative_to(base).parts
        self._thread_lock = threading.RLock()
        # Storage-authentication key source (profile secret scope); None = no authenticated storage.
        self.key_provider: Callable[[], bytes | None] | None = None
        # Central mutation guard (broker operation lease): every durable write runs inside it, so a
        # revoked/expired grant can never mutate after loss. None = unguarded (engine-only unit use).
        self.commit_gate: Callable[[], Any] | None = None
        base.mkdir(parents=True, exist_ok=True)
        os.close(pinned_fs.open_chain(self._base, self._parts))
        self._drop_legacy_route_key()

    @contextlib.contextmanager
    def _commit(self):
        gate = self.commit_gate
        with (gate() if gate is not None else contextlib.nullcontext()):
            yield

    def _atomic(self, *args: Any, **kwargs: Any) -> bool:
        with self._commit():
            return pinned_fs.write_atomic(*args, **kwargs)

    @contextlib.contextmanager
    def _root_fd(self):
        fd = pinned_fs.open_chain(self._base, self._parts)
        try:
            yield fd
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _conv(self, conversation_id: str, *, create: bool = True):
        conv = _segment(conversation_id, "conversation_id")
        with self._root_fd() as root_fd:
            fd = pinned_fs.open_child(root_fd, conv, create=create)
            try:
                yield fd
            finally:
                os.close(fd)

    @contextlib.contextmanager
    def _locked(self, conversation_id: str):
        with self._thread_lock, self._conv(conversation_id) as conv_fd:
            lock_fd = os.open(".lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=conv_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                yield conv_fd
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    def _rows(self, conv_fd: int) -> list[dict[str, Any]]:
        """Parse the journal. Callers hold the conversation lock.

        Each record is one ``json\\n`` write, so a crash can only leave a single incomplete FINAL
        record. That tail is quarantined (never silently trusted) and the file is repaired so the
        next append starts on a clean line. A malformed complete or interior record means
        corruption/tampering and fails closed."""
        try:
            raw = pinned_fs.read_bytes(conv_fd, "events.jsonl")
        except ValueError:
            return []
        *complete, tail = raw.split(b"\n")
        rows: list[dict[str, Any]] = []
        for line in complete:
            if not line.strip():
                continue
            try:
                row = json.loads(line.decode("utf-8"))
            except ValueError as exc:
                raise ValueError("journal_corrupt") from exc
            if not isinstance(row, dict):
                raise ValueError("journal_corrupt")
            rows.append(row)
        if tail.strip():
            try:
                row = json.loads(tail.decode("utf-8"))
                torn = not isinstance(row, dict)
            except ValueError:
                torn = True
            if torn:
                self._atomic(conv_fd, f"events.torn-{time.time_ns()}", tail)
            else:
                rows.append(row)
            good = b"".join(line + b"\n" for line in complete) + (b"" if torn else tail + b"\n")
            self._atomic(conv_fd, "events.jsonl", good, replace=True)
        return rows

    def _put(self, conv_fd: int, event: dict[str, Any]) -> None:
        if {"text", "value", "content", "error"}.intersection(event):
            raise ValueError("queue_or_audit_must_not_contain_payload")
        with self._commit():
            pinned_fs.append_bytes(conv_fd, "events.jsonl",
                                   (json.dumps({"at": time.time(), **event}, sort_keys=True) + "\n").encode())

    def append(self, conversation_id: str, event: dict[str, Any]) -> None:
        with self._locked(conversation_id) as conv_fd:
            self._put(conv_fd, event)

    def events(self, conversation_id: str) -> list[dict[str, Any]]:
        with self._locked(conversation_id) as conv_fd:
            return self._rows(conv_fd)

    def verify_writable(self) -> bool:
        with self._root_fd() as root_fd:
            return os.access(".", os.W_OK, dir_fd=root_fd)

    # projections: the designated masked payload store (payload only here, never in events)
    # --- keyed storage authentication (separate from network envelope/peer authentication) --
    def _skey(self) -> bytes | None:
        if self.key_provider is None:
            return None
        try:
            return self.key_provider()
        except AuthorityLost:
            raise
        except Exception:
            return None

    @staticmethod
    def _smac(key: bytes, domain: str, obj: Any) -> str:
        body = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hmac.new(key, f"hermes/thread-storage/{domain}/v1\0".encode() + body, hashlib.sha256).hexdigest()

    def _envelope_tag(self, key: bytes, data: dict[str, Any], scope: str) -> str:
        """Schema-complete: EVERY ThreadEnvelope field (current and future) plus the storage scope, so a
        file copied to another conversation/message path can never validate."""
        bound = {f.name: data.get(f.name) for f in fields(ThreadEnvelope)}
        bound["__scope__"] = scope
        return self._smac(key, "envelope", bound)

    def save_projection(self, envelope: ThreadEnvelope) -> str:
        name = f"{_segment(envelope.message_id, 'message_id')}.json"
        body = asdict(envelope)
        if self.key_provider is not None:
            key = self._skey()
            if key is None:
                raise ValueError("storage_key_unavailable")  # never persist unauthenticated artifacts
            body["_mac"] = self._envelope_tag(key, body, f"projection|{envelope.conversation_id}|{envelope.message_id}")
        data = json.dumps(body, sort_keys=True).encode()
        with self._locked(envelope.conversation_id) as conv_fd:
            proj_fd = pinned_fs.open_child(conv_fd, "projections")
            try:
                self._atomic(proj_fd, name, data)
            finally:
                os.close(proj_fd)
        return f"{envelope.conversation_id}/projections/{name}"

    def compare_or_create_projection(self, envelope: ThreadEnvelope) -> tuple[str, ThreadEnvelope | None]:
        """ONE atomic step under the conversation lock + pinned dir_fd: create the authenticated projection
        or compare against the existing one. Returns (CREATED | EXACT_REPLAY | CONFLICT | TAMPERED,
        canonical stored envelope). Callers must continue ONLY with the returned canonical object."""
        name = f"{_segment(envelope.message_id, 'message_id')}.json"
        body = asdict(envelope)
        scope = f"projection|{envelope.conversation_id}|{envelope.message_id}"
        if self.key_provider is not None:
            key = self._skey()
            if key is None:
                return "TAMPERED", None
            body["_mac"] = self._envelope_tag(key, body, scope)
        data = json.dumps(body, sort_keys=True).encode()
        with self._locked(envelope.conversation_id) as conv_fd:
            proj_fd = pinned_fs.open_child(conv_fd, "projections")
            try:
                if self._atomic(proj_fd, name, data):
                    return "CREATED", envelope
                try:
                    raw = pinned_fs.read_bytes(proj_fd, name)
                except ValueError:
                    return "TAMPERED", None
                status, stored = self._verified_projection(raw, envelope.conversation_id, envelope.message_id)
                if stored is None:
                    return "TAMPERED", None
                return ("EXACT_REPLAY" if stored.replay_digest == envelope.replay_digest else "CONFLICT"), stored
            finally:
                os.close(proj_fd)

    def append_once(self, conversation_id: str, event: dict[str, Any]) -> bool:
        """Append unless a row with the same kind+message_id exists (atomic under the lock)."""
        with self._locked(conversation_id) as conv_fd:
            if any(r.get("kind") == event["kind"] and r.get("message_id") == event.get("message_id")
                   for r in self._rows(conv_fd)):
                return False
            self._put(conv_fd, event)
            return True

    def _verified_projection(self, raw: bytes, conversation_id: str,
                             message_id: str) -> tuple[str, ThreadEnvelope | None]:
        """("valid"|"tampered"|"unavailable"|"plain", envelope): MAC checked BEFORE the data is used."""
        try:
            data = json.loads(raw)
            mac = data.pop("_mac", None)
        except (ValueError, AttributeError):
            return "tampered", None
        if self.key_provider is not None:
            key = self._skey()
            if key is None:
                return "unavailable", None
            if not isinstance(mac, str) or not hmac.compare_digest(mac, self._envelope_tag(key, data, f"projection|{conversation_id}|{message_id}")):
                return "tampered", None
        try:
            env = ThreadEnvelope(**data)
        except (TypeError, ValueError):
            return "tampered", None
        if env.conversation_id != conversation_id or env.message_id != message_id:
            return "tampered", None  # identity must equal the requested storage location
        return ("valid" if self.key_provider is not None else "plain"), env

    def load_projection(self, conversation_id: str, message_id: str) -> ThreadEnvelope:
        name = f"{_segment(message_id, 'message_id')}.json"
        with self._conv(conversation_id, create=False) as conv_fd:
            proj_fd = pinned_fs.open_child(conv_fd, "projections", create=False)
            try:
                status, env = self._verified_projection(pinned_fs.read_bytes(proj_fd, name), conversation_id, message_id)
            finally:
                os.close(proj_fd)
        if env is None:
            raise ValueError(f"storage_{status}")
        return env

    # --- durable, non-secret routing reference (never message text) -------------------------
    def _route_mac(self, route: dict[str, Any]) -> str:
        """Route authenticity: profile-secret derived storage key (domain "route"), never a sidecar key."""
        key = self._skey()
        if key is None:
            raise ValueError("storage_key_unavailable")
        return self._smac(key, "route", {k: route[k] for k in sorted(route) if k != "mac"})

    def _drop_legacy_route_key(self) -> None:
        """`route_key.bin` (attacker-readable, written by an earlier revision of this feature) is no longer
        an authority: remove it. Routes it signed fail the new MAC (fail closed, explicit manual state)."""
        try:
            with self._root_fd() as root_fd:
                os.unlink("route_key.bin", dir_fd=root_fd)
        except OSError:
            pass

    def save_route(self, conversation_id: str, message_id: str, route: dict[str, Any]) -> None:
        """Bind (kind, peer/recipient, target thread) to a message; the first stored route wins."""
        record = {**route, "conversation_id": conversation_id, "message_id": _segment(message_id, "message_id"),
                  "__scope__": f"route|{conversation_id}|{message_id}"}
        record["mac"] = self._route_mac(record)
        with self._locked(conversation_id) as conv_fd:
            routes_fd = pinned_fs.open_child(conv_fd, "routes")
            try:
                self._atomic(routes_fd, f"{message_id}.json", json.dumps(record, sort_keys=True).encode())
            finally:
                os.close(routes_fd)

    def load_route(self, conversation_id: str, message_id: str) -> dict[str, Any]:
        """Pinned/no-follow read + MAC check. Missing or altered routes raise (fail closed)."""
        try:
            with self._conv(conversation_id, create=False) as conv_fd:
                routes_fd = pinned_fs.open_child(conv_fd, "routes", create=False)
                try:
                    record = json.loads(pinned_fs.read_bytes(routes_fd, f"{_segment(message_id, 'message_id')}.json"))
                finally:
                    os.close(routes_fd)
        except (ValueError, OSError) as exc:
            raise ValueError("route_fehlt") from exc
        if not isinstance(record, dict) or not isinstance(record.get("mac"), str):
            raise ValueError("route_manipuliert")
        try:
            expected = self._route_mac(record)
        except ValueError as exc:
            raise ValueError("route_unbelegt") from exc  # secret scope unavailable: fail closed
        if not hmac.compare_digest(record["mac"], expected) \
                or record.get("conversation_id") != conversation_id or record.get("message_id") != message_id \
                or record.get("__scope__") != f"route|{conversation_id}|{message_id}":
            raise ValueError("route_manipuliert")
        return record

    # --- durable recipient dispatch inbox (PENDING -> RUNNING -> ACCEPTED -> DONE) -----------
    # One record per authenticated (tenant, conversation, message, recipient). RUNNING is the gateway's
    # atomic, fenced claim taken BEFORE the model is invoked: RUNNING/ACCEPTED/DONE never submit again.
    _DISPATCH_KINDS = {"dispatch_pending": "PENDING", "dispatch_running": "RUNNING",
                       "dispatch_accepted": "ACCEPTED", "dispatch_released": "RELEASED", "dispatch_done": "DONE",
                       "dispatch_reply_pending": "REPLY_PENDING",  # masked model reply persisted; projection/finalize outstanding
                       "dispatch_replied": "REPLIED",  # authenticated reply durable (or typed no-reply)
                       "dispatch_completed": "COMPLETED",  # MODEL_COMPLETED, terminal record not yet written
                       "inbound_processed": "DONE"}  # inbound_processed = the ONE terminal record

    @classmethod
    def _dispatch_row(cls, rows: list[dict[str, Any]], message_id: str) -> dict[str, Any] | None:
        last = None
        for r in rows:
            if r.get("kind") in cls._DISPATCH_KINDS and r.get("message_id") == message_id:
                last = r
        return last

    @classmethod
    def _dispatch_last(cls, rows: list[dict[str, Any]], message_id: str) -> str | None:
        last = cls._dispatch_row(rows, message_id)
        return cls._DISPATCH_KINDS[last["kind"]] if last else None

    def dispatch_enqueue(self, conversation_id: str, message_id: str, key: str) -> str:
        """Idempotent durable enqueue (PENDING). Returns the current record state."""
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            state = self._dispatch_last(rows, message_id)
            if state is None:
                self._put(conv_fd, {"kind": "dispatch_pending", "conversation_id": conversation_id,
                                    "message_id": message_id, "key": key})
                return "PENDING"
            return state

    def dispatch_state(self, conversation_id: str, message_id: str) -> str | None:
        return self.dispatch_info(conversation_id, message_id)[0]

    def dispatch_info(self, conversation_id: str, message_id: str) -> tuple[str | None, float]:
        """(state, lease expiry of a RUNNING claim)."""
        with self._locked(conversation_id) as conv_fd:
            row = self._dispatch_row(self._rows(conv_fd), message_id)
            if row is None:
                return None, 0.0
            return self._DISPATCH_KINDS[row["kind"]], float(row.get("expires_at") or 0.0)

    def dispatch_transition(self, conversation_id: str, message_id: str, kind: str, *, expect: set[str],
                            token: str, fence: int, key: str = "", now: float | None = None,
                            lease: float = 0.0, resubmit_expired: bool = False, replier: str = "") -> bool:
        """Atomic state change, valid only for the CURRENT stage claimant (token + fence). A RUNNING
        record whose lease expired may be re-claimed (``resubmit_expired``): the crash contract is
        at-least-once model execution under the SAME dispatch key."""
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            window, _ = self._window(rows, message_id, "dispatch")
            claims = [r for r in window if r["kind"] == "claim"]
            if not (claims and claims[-1]["token"] == token and claims[-1]["fence"] == fence):
                return False
            if kind == "dispatch_running" and self._evidence(conv_fd, conversation_id, message_id, replier)[0] != "none":
                return False  # a durable (or tampered) reply exists: no model may EVER start for this key
            last = self._dispatch_row(rows, message_id)
            state = self._DISPATCH_KINDS[last["kind"]] if last else None
            expired = (resubmit_expired and state in {"RUNNING", "ACCEPTED", "COMPLETED"} and now is not None
                       and float(last.get("expires_at") or 0.0) <= now)
            if state not in expect and not expired:
                return False
            row = {"kind": kind, "conversation_id": conversation_id, "message_id": message_id,
                   "token": token, "fence": fence, "key": key}
            if kind in {"dispatch_running", "dispatch_accepted"} and now is not None:
                row["expires_at"] = now + lease
            self._put(conv_fd, row)
            return True

    def dispatch_mark_completed(self, conversation_id: str, message_id: str, key: str,
                                now: float | None = None) -> bool:
        """MODEL_COMPLETED (nonterminal): the model run finished. The reply is NOT yet durable, so a
        crash now must lead to a re-run, never to a duplicate. Lease-bound so an in-flight reply
        finalization is not raced."""
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            row = self._dispatch_row(rows, message_id)
            state = self._DISPATCH_KINDS[row["kind"]] if row else None
            if state in {"COMPLETED", "REPLY_PENDING", "REPLIED", "DONE"}:
                return True
            if state not in {"RUNNING", "ACCEPTED"} or not key or row.get("key") != key:
                return False
            entry = {"kind": "dispatch_completed", "conversation_id": conversation_id,
                     "message_id": message_id, "key": key}
            if now is not None:
                entry["expires_at"] = now + CLAIM_LEASE_SECONDS
            self._put(conv_fd, entry)
            return True

    def dispatch_mark_reply_pending(self, conversation_id: str, message_id: str, key: str) -> bool:
        """The model's masked reply is durably stored; the model must NEVER be re-run for this key."""
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            row = self._dispatch_row(rows, message_id)
            state = self._DISPATCH_KINDS[row["kind"]] if row else None
            if state in {"REPLY_PENDING", "REPLIED", "DONE"}:
                return True
            if state not in {"RUNNING", "ACCEPTED", "COMPLETED"} or not key or row.get("key") != key:
                return False
            self._put(conv_fd, {"kind": "dispatch_reply_pending", "conversation_id": conversation_id,
                                "message_id": message_id, "key": key})
            return True

    # ---- durable model reply: ONE invariant -----------------------------------------------
    # The reply file (fsynced, MAC-authenticated, keyed by the stable dispatch key) IS the commit point.
    # Its existence forbids any model (re)start for the message, with or without the REPLY_PENDING row;
    # an orphaned file (crash before the row) is validated and promoted before anything else happens.
    def _reply_record(self, conversation_id: str, message_id: str, key: str, record: dict[str, Any]) -> dict[str, Any]:
        skey = self._skey()
        if skey is None:
            raise ValueError("storage_key_unavailable")
        body = {**record, "conversation_id": conversation_id, "message_id": message_id, "key": key,
                "__scope__": f"reply|{conversation_id}|{message_id}",
                "text_digest": hashlib.sha256(str(record.get("text", "")).encode("utf-8")).hexdigest()}
        body["mac"] = self._smac(skey, "reply", body)
        return body

    def save_pending_reply(self, conversation_id: str, message_id: str, record: dict[str, Any],
                           key: str = "") -> None:
        """Designated masked payload store (first write wins: the stored reply is the reply)."""
        body = self._reply_record(conversation_id, message_id, key, record)
        with self._locked(conversation_id) as conv_fd:
            rep_fd = pinned_fs.open_child(conv_fd, "replies")
            try:
                self._atomic(rep_fd, f"{_segment(message_id, 'message_id')}.json",
                                       json.dumps(body, sort_keys=True).encode())
            finally:
                os.close(rep_fd)

    def _read_reply_fd(self, conv_fd: int, conversation_id: str, message_id: str) -> tuple[str, dict[str, Any] | None]:
        """("none"|"valid"|"invalid", record) from an already pinned conversation fd."""
        try:
            rep_fd = pinned_fs.open_child(conv_fd, "replies", create=False)
        except ValueError:
            return "none", None
        try:
            try:
                raw = pinned_fs.read_bytes(rep_fd, f"{_segment(message_id, 'message_id')}.json")
            except ValueError:
                return "none", None
            try:
                record = json.loads(raw)
            except ValueError:
                return "tampered", None
            skey = self._skey()
            if skey is None:
                return "unavailable", None  # secret unavailable/rotated: explicit manual state, no model run
            body = {k: v for k, v in record.items() if k != "mac"} if isinstance(record, dict) else {}
            ok = (isinstance(record, dict) and isinstance(record.get("mac"), str)
                  and hmac.compare_digest(record["mac"], self._smac(skey, "reply", body))
                  and record.get("message_id") == message_id and record.get("conversation_id") == conversation_id
                  and record.get("__scope__") == f"reply|{conversation_id}|{message_id}"
                  and isinstance(record.get("text"), str)
                  and record.get("text_digest") == hashlib.sha256(record["text"].encode("utf-8")).hexdigest())
            return ("valid", record) if ok else ("tampered", None)
        finally:
            os.close(rep_fd)

    def _evidence(self, conv_fd: int, conversation_id: str, message_id: str,
                  replier: str) -> tuple[str, dict[str, Any] | None]:
        """Authoritative NO_RERUN evidence, strongest artifact first: the pending-reply file, else the
        replier's validated masked reply projection (the first fsynced artifact of `send_reply`)."""
        status, record = self._read_reply_fd(conv_fd, conversation_id, message_id)
        if status != "none" or not replier:
            return status, record
        rid = reply_id_for(conversation_id, message_id, replier)
        try:
            proj_fd = pinned_fs.open_child(conv_fd, "projections", create=False)
        except ValueError:
            return "none", None
        try:
            try:
                raw = pinned_fs.read_bytes(proj_fd, f"{rid}.json")
            except ValueError:
                return "none", None
            status, env = self._verified_projection(raw, conversation_id, rid)
            if status in {"tampered", "unavailable"}:
                return status, None
            if self.key_provider is None:
                return "unavailable", None  # reply evidence is only trusted through authenticated storage
            ok = (env.parent_message_id == message_id and env.sender == replier
                  and env.conversation_id == conversation_id
                  and isinstance(env.masking, dict)
                  and env.masking.get("digest") == hashlib.sha256(env.text.encode("utf-8")).hexdigest())
            return ("valid", {"key": None, "text": env.text, "source": "projection"}) if ok else ("tampered", None)
        finally:
            os.close(proj_fd)

    def load_pending_reply(self, conversation_id: str, message_id: str) -> dict[str, Any] | None:
        try:
            with self._conv(conversation_id, create=False) as conv_fd:
                status, record = self._read_reply_fd(conv_fd, conversation_id, message_id)
                return record if status == "valid" else None
        except (ValueError, OSError):
            return None

    def reply_status(self, conversation_id: str, message_id: str, key: str = "", replier: str = "") -> str:
        """Authoritative orphan detection + promotion. "none": no durable reply (the model may run).
        "valid": a durable, storage-authenticated reply exists; the dispatch row is promoted to
        REPLY_PENDING if the crash happened before it was written. "tampered" / "unavailable" (forged or
        torn artifact; storage secret unavailable or rotated): fail closed, the model is never re-run."""
        with self._locked(conversation_id) as conv_fd:
            status, record = self._evidence(conv_fd, conversation_id, message_id, replier)
            if status != "valid":
                return status
            if key and record.get("key") not in (key, None):
                return "tampered"
            rows = self._rows(conv_fd)
            row = self._dispatch_row(rows, message_id)
            state = self._DISPATCH_KINDS[row["kind"]] if row else None
            if state in {"REPLY_PENDING", "REPLIED", "DONE"}:
                return "valid"
            self._put(conv_fd, {"kind": "dispatch_reply_pending", "conversation_id": conversation_id,
                                "message_id": message_id, "key": key or record.get("key") or (row or {}).get("key") or "",
                                "promoted": True})
            return "valid"

    def pending_reply_ids(self, conversation_id: str) -> list[str]:
        try:
            with self._conv(conversation_id, create=False) as conv_fd:
                rep_fd = pinned_fs.open_child(conv_fd, "replies", create=False)
                try:
                    return [n[:-5] for n in pinned_fs.list_names(rep_fd) if n.endswith(".json")]
                finally:
                    os.close(rep_fd)
        except (ValueError, OSError):
            return []

    def dispatch_mark_replied(self, conversation_id: str, message_id: str, key: str, *,
                              no_reply: bool = False) -> bool:
        """The authenticated reply is durable (or the turn intentionally has none: typed `no_reply`)."""
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            row = self._dispatch_row(rows, message_id)
            state = self._DISPATCH_KINDS[row["kind"]] if row else None
            if state in {"REPLIED", "DONE"}:
                return True
            if state not in {"RUNNING", "ACCEPTED", "COMPLETED", "REPLY_PENDING"} or not key \
                    or row.get("key") != key:
                return False
            self._put(conv_fd, {"kind": "dispatch_replied", "conversation_id": conversation_id,
                                "message_id": message_id, "key": key, "no_reply": bool(no_reply)})
            return True

    def complete_dispatch(self, conversation_id: str, message_id: str, *, token: str, fence: int,
                          masking: dict[str, Any], key: str = "", require_replied: bool = False) -> bool:
        """ONE terminal record. `inbound_processed` (stage=dispatch) is simultaneously the claim's
        completion, the queue entry's terminal status and the dispatch record's DONE, written by a
        single fsynced append under the lock: a crash leaves it fully absent or fully present.
        Allowed for the live claim holder, or by dispatch identity once the model ran (key)."""
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            if any(r.get("kind") == "inbound_processed" and r.get("message_id") == message_id for r in rows):
                return True  # idempotent: already terminal
            window, _ = self._window(rows, message_id, "dispatch")
            claims = [r for r in window if r["kind"] == "claim"]
            holder = bool(claims and claims[-1]["token"] == token and claims[-1]["fence"] == fence)
            row = self._dispatch_row(rows, message_id)
            by_key = bool(row and key and row.get("key") == key
                          and self._DISPATCH_KINDS[row["kind"]] in {"RUNNING", "ACCEPTED", "COMPLETED", "REPLIED"})
            if require_replied:  # conversational turn: terminal ONLY after the reply is durable
                if not (row and key and row.get("key") == key and self._DISPATCH_KINDS[row["kind"]] == "REPLIED"):
                    return False
            elif not (holder or by_key):
                return False
            self._put(conv_fd, {"kind": "inbound_processed", "stage": "dispatch",
                                "conversation_id": conversation_id, "message_id": message_id, "token": token,
                                "fence": fence, "status": "empfangen", "masking": masking})
            return True

    def conversations(self) -> list[str]:
        with self._root_fd() as root_fd:
            return [n for n in pinned_fs.list_names(root_fd) if _SAFE_ID.fullmatch(n)]

    # --- atomic claim / fencing -------------------------------------------------
    @staticmethod
    def _window(rows: list[dict[str, Any]], message_id: str, stage: str) -> tuple[list[dict[str, Any]], int]:
        mine = [r for r in rows if r.get("message_id") == message_id and r.get("stage") == stage]
        reset = max((i for i, r in enumerate(mine) if r["kind"] == "stage_failed"), default=-1)
        fence = max((int(r.get("fence", 0)) for r in mine if r["kind"] == "claim"), default=0)
        return mine[reset + 1:], fence

    def claim(self, conversation_id: str, message_id: str, stage: str, *, token: str, now: float,
              resend_safe: bool = False) -> dict[str, Any]:
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            window, fence = self._window(rows, message_id, stage)
            done = next((r for r in window if r["kind"] in {"stage_done", "inbound_processed"}), None)
            if done:
                return {"state": "done", "ref": done.get("ref", "")}
            claims = [r for r in window if r["kind"] == "claim"]
            intent = any(r["kind"] == "stage_intent" for r in window)
            if claims:
                last = claims[-1]
                if last["expires_at"] > now and last["token"] != token:
                    return {"state": "busy"}
                if intent and not resend_safe:
                    return {"state": "ambiguous"}
            self._put(conv_fd, {"kind": "claim", "conversation_id": conversation_id, "message_id": message_id,
                                "stage": stage, "token": token, "fence": fence + 1,
                                "expires_at": now + CLAIM_LEASE_SECONDS})
            return {"state": "claimed", "fence": fence + 1}

    def mark(self, conversation_id: str, kind: str, message_id: str, stage: str, *, token: str, fence: int,
             ref: str = "") -> bool:
        with self._locked(conversation_id) as conv_fd:
            rows = self._rows(conv_fd)
            window, _ = self._window(rows, message_id, stage)
            claims = [r for r in window if r["kind"] == "claim"]
            if not (claims and claims[-1]["token"] == token and claims[-1]["fence"] == fence):
                return False  # fenced out by a newer claimant
            self._put(conv_fd, {"kind": kind, "conversation_id": conversation_id, "message_id": message_id,
                                "stage": stage, "token": token, "fence": fence, "ref": ref})
            return True


# --------------------------------------------------------------------------- machines


def derive_storage_key(secrets: Iterable[str], tenant: str, profile: str) -> bytes | None:
    """Local storage-authentication key, derived ONLY from the recipient profile's existing secret scope
    (never stored, never generated, no env/config fallback). Domain-separated and bound to tenant +
    profile, so another profile/tenant cannot validate this profile's artifacts. Unavailable or rotated
    secret material yields None / a different key -> artifacts fail closed."""
    values = sorted(v for v in secrets if isinstance(v, str) and v)
    if not values or not tenant or not profile:
        return None
    root = hashlib.sha256(b"\0".join(v.encode("utf-8") for v in values)).digest()
    return hmac.new(root, f"hermes/thread-storage/key/v1|{tenant}|{profile}".encode("utf-8"),
                    hashlib.sha256).digest()



def reply_id_for(conversation_id: str, inbound_message_id: str, replier: str) -> str:
    """Stable identity of the reply to one inbound message (a re-run can never create a second reply)."""
    return hashlib.sha256(f"reply|{conversation_id}|{inbound_message_id}|{replier}".encode()).hexdigest()[:24]


def dispatch_key(tenant: str | None, conversation_id: str, message_id: str, recipient: str) -> str:
    """Stable recipient task identity from the authenticated (tenant, conversation, message, recipient)."""
    return hashlib.sha256(f"{tenant}|{conversation_id}|{message_id}|{recipient}".encode()).hexdigest()


def egress_key(conversation_id: str, message_id: str, stage: str, thread: dict[str, Any]) -> str:
    return hashlib.sha256(
        f"{conversation_id}|{message_id}|{stage}|{thread['chat_id']}:{thread['thread_id']}".encode()).hexdigest()


class _Machine:
    def __init__(self, sync: "ThreadSync"):
        self.sync = sync

    def _audit(self, event: ThreadEnvelope, status: str, reason: str = "") -> None:
        self.sync.journal.append(event.conversation_id, {
            "kind": "audit", "conversation_id": event.conversation_id, "message_id": event.message_id,
            "parent_message_id": event.parent_message_id, "sender": event.sender, "recipient": event.recipient,
            "tenant": event.tenant, "tenant_source": event.tenant_source, "transport": event.transport,
            "spiegel": event.spiegel, "status": status, "reason": reason,
            "match_count": event.masking.get("match_count", 0),
            "scanner_version": event.masking.get("scanner_version", SCANNER_VERSION),
        })

    def _canonical(self, event: ThreadEnvelope) -> tuple[ThreadEnvelope | None, SyncResult | None]:
        """Canonicalize through the atomic compare-or-create. The submitted object is never used after
        this call; a conflicting or tampered identity blocks with zero further side effects."""
        result, canonical = self.sync.journal.compare_or_create_projection(event)
        if result == "TAMPERED":
            return None, SyncResult("blocked", "projektion_manipuliert", message_id=event.message_id)
        if result == "CONFLICT":
            return None, SyncResult("blocked", "message_id_conflict", message_id=event.message_id)
        return canonical, None

    def _block(self, event: ThreadEnvelope, reason: str) -> SyncResult:
        try:
            self._audit(event, "blocked", reason)
        except AuthorityLost:
            pass  # authority is gone: no audit row is written after loss
        return SyncResult("blocked", reason, message_id=event.message_id)

    def _gate(self, event: ThreadEnvelope, *required: str) -> str | None:
        ctx = self.sync.auth
        if self.sync.authority is not None and not self.sync.authority():
            return "autoritaet_widerrufen"
        reason = ctx.invalid(self.sync.clock())
        if reason:
            return reason
        if event.tenant is not None and event.tenant != ctx.tenant:
            return "tenant_abweichend"
        missing = self.sync.evidence.require(*required)
        if missing == "tenant":
            return "tenant_unbekannt"
        return "spiegel_unbelegt" if missing else None

    def _owner(self, thread: dict[str, Any]) -> tuple[Owner | None, str | None]:
        ctx = self.sync.auth
        if _norm(thread) != _norm(ctx.thread):
            return None, "owner_abweichend"
        resolved = self.sync.owner_resolver(thread)
        if isinstance(resolved, list):
            if len(resolved) != 1:
                return None, "owner_mehrdeutig"
            resolved = resolved[0]
        if resolved is None:
            return None, "kein_aktiver_owner"
        if (resolved.profile_home, resolved.profile, resolved.live_session_id) != \
                (ctx.profile_home, ctx.profile, ctx.live_session_id) \
                or (resolved.chat_id, resolved.thread_id) != (thread["chat_id"], thread["thread_id"]):
            return None, "owner_abweichend"
        return resolved, resolved.valid(self.sync.clock())

    def _stage(self, event: ThreadEnvelope, stage: str, fn: Callable[[], str], *, resend_safe: bool = False) -> tuple[str, str]:
        j, token, conv, msg = self.sync.journal, self.sync.token, event.conversation_id, event.message_id
        claim = j.claim(conv, msg, stage, token=token, now=self.sync.clock(), resend_safe=resend_safe)
        if claim["state"] != "claimed":
            return claim["state"], claim.get("ref", "")
        fence = claim["fence"]
        if not j.mark(conv, "stage_intent", msg, stage, token=token, fence=fence):
            return "busy", ""
        try:
            ref = str(fn() or "")
        except Exception:
            j.mark(conv, "stage_failed", msg, stage, token=token, fence=fence)
            raise
        if not j.mark(conv, "stage_done", msg, stage, token=token, fence=fence, ref=ref[:128]):
            return "busy", ""  # a newer claimant owns the stage; never complete it on its behalf
        return "done", ref

    def _masked(self, event: ThreadEnvelope) -> ThreadEnvelope:
        masked = mask_text(event.text, secrets=self.sync.current_secrets())
        return ThreadEnvelope(**{**asdict(event), "text": masked.text, "masking": masked.proof()})

    def _queue(self, event: ThreadEnvelope, direction: str, reason: str, attempts: int, prior: dict | None,
               dispatch: str = "local") -> None:
        now = self.sync.clock()
        self.sync.journal.append(event.conversation_id, {
            "kind": "eingereiht" if attempts == 0 else "versuch", "direction": direction, "conversation_id": event.conversation_id,
            "message_id": event.message_id, "attempts": attempts, "reason": reason,
            "dispatch": dispatch,  # how recovery must hand the message on; a type, never content
            "dispatch_kind": event.transport,  # a2a | message_agent: which recipient dispatcher is required
            "next_at": now + (5 if attempts == 0 else OutboundStateMachine._delay(attempts)),
            "enqueued_at": float(prior.get("enqueued_at", now)) if prior else now,
        })


class OutboundStateMachine(_Machine):
    @staticmethod
    def _delay(attempts: int) -> int:
        return min(BACKOFF_CAP_SECONDS, 5 * (2 ** max(0, attempts - 1)))

    def _failed_status(self, event: ThreadEnvelope, reason: str) -> None:
        """A terminal status only edits the original sender projection, never sends a follow-up."""
        result = self.update_status(event, "fehlgeschlagen", reason=reason)
        # If the initial projection itself never reached the platform, there is no entry to edit.
        # One terminal error projection is then the sole visible entry; once a reference exists, the
        # branch above is the only path and no follow-up can be emitted.
        existing = self.sync.journal.events(event.conversation_id)
        has_projection = any(row.get("message_id") == event.message_id and row.get("sender_projection")
                             for row in existing)
        if result.status != "unvollständig" or has_projection:
            return
        owner, bad = self._owner(event.source_thread)
        if owner is None or bad or self.sync.sender_project is None:
            return
        payload = {**asdict(event), "spiegel": True, "text": f"Zustellung fehlgeschlagen ({reason}).",
                   "status": "fehlgeschlagen", "egress_key": egress_key(event.conversation_id, event.message_id,
                                                                            "status", event.source_thread)}
        with contextlib.suppress(Exception):
            self._stage(event, "status", lambda: self.sync.sender_project(owner, payload))

    def update_status(self, event: ThreadEnvelope, status: str, *, reason: str = "") -> SyncResult:
        """Edit the first sender projection for this message, with a separately idempotent egress key."""
        if status not in {"empfangen", "beantwortet", "fehlgeschlagen"}:
            return SyncResult("unvollständig", "status_unzulaessig", message_id=event.message_id)
        existing = self.sync.journal.events(event.conversation_id)
        projection = next((row for row in reversed(existing)
                           if row.get("message_id") == event.message_id and row.get("sender_projection")), None)
        reference = str((projection or {}).get("sender_projection") or "")
        owner, bad = self._owner(event.source_thread)
        if not reference or owner is None or bad or self.sync.sender_edit is None:
            self._audit(event, "unvollständig", "bearbeiten_nicht_unterstuetzt")
            return SyncResult("unvollständig", "bearbeiten_nicht_unterstuetzt", message_id=event.message_id)
        text = (f"Zustellung fehlgeschlagen ({reason})." if status == "fehlgeschlagen"
                else f"Status: {status}.")
        payload = {**asdict(event), "spiegel": True, "text": text, "status": status,
                   "egress_key": egress_key(event.conversation_id, event.message_id,
                                             f"sender_edit:{status}", event.source_thread)}
        try:
            def edit() -> str:
                result = self.sync.sender_edit(owner, reference, payload)
                if not isinstance(result, dict) or not result.get("success"):
                    raise RuntimeError("bearbeiten_nicht_unterstuetzt")
                return reference
            state, _ = self._stage(event, f"sender_edit:{status}", edit)
        except Exception:
            self._audit(event, "unvollständig", "bearbeiten_nicht_unterstuetzt")
            return SyncResult("unvollständig", "bearbeiten_nicht_unterstuetzt", message_id=event.message_id)
        if state != "done":
            return SyncResult("unvollständig", "bearbeiten_nicht_unterstuetzt", message_id=event.message_id)
        self.sync.journal.append_once(event.conversation_id, {
            "kind": "sender_status", "conversation_id": event.conversation_id, "message_id": event.message_id,
            "sender_projection": reference, "spiegel": True, "status": status, "reason": reason,
        })
        self._audit(event, status, reason)
        return SyncResult(status, reason, message_id=event.message_id)

    def dead_letter(self, event: ThreadEnvelope, reason: str, attempts: int) -> SyncResult:
        self.sync.journal.append(event.conversation_id, {
            "kind": "dead_letter", "direction": "out", "conversation_id": event.conversation_id,
            "message_id": event.message_id, "status": "fehlgeschlagen", "reason": reason, "attempts": attempts})
        self._failed_status(event, reason)
        return SyncResult("dead_letter", reason, attempts, event.message_id)

    def send(self, event: ThreadEnvelope, *, force: bool = False, canonical: bool = False) -> SyncResult:
        existing = self.sync.journal.events(event.conversation_id)
        prior = next((r for r in reversed(existing) if _ist(r, "eingereiht", "versuch")
                      and r.get("message_id") == event.message_id), None)
        if event.is_root is False and not any(r.get("message_id") == event.parent_message_id and r.get("kind") in
                                              {"inbound_receipt"} or _ist(r, "bestaetigt") for r in existing):
            return self._block(event, "parent_unbekannt")
        if event.art == "arbeitsauftrag" and not event.projection_requested:
            return SyncResult("ignored", "arbeitsauftrag_ohne_projektion", message_id=event.message_id)
        ctx = self.sync.auth
        if event.tenant is None:  # authority is the authenticated context, never the message
            event = ThreadEnvelope(**{**asdict(event), "tenant": ctx.tenant, "tenant_source": "kontext"})
        reason = self._gate(event, "provider_binding", "tenant", "egress", "sender_edit", "audit")
        if reason:
            return self._block(event, reason)
        if not self.sync.journal.verify_writable():
            return SyncResult("blocked", "audit_fehler", message_id=event.message_id)
        if event.transport == "a2a":
            if not self.sync.evidence.proven("a2a_ids"):
                return SyncResult("blocked", "a2a_id_unbelegt", message_id=event.message_id)
            if not self.sync.evidence.proven("a2a_ablage"):
                return SyncResult("blocked", "a2a_ablage_unmaskiert", message_id=event.message_id)
        if _norm(event.source_thread) != _norm(ctx.thread):
            return self._block(event, "owner_abweichend")
        try:
            if not canonical:  # a stored canonical envelope is already masked + authenticated
                event = self._masked(event)
        except Exception:
            return self._block(event, "scan_fehler")
        if self.sync.sender_project is None:
            return self._block(event, "spiegel_unbelegt")
        event, refused = self._canonical(event)  # FIRST: identity is validated before any idempotent shortcut
        if refused is not None:
            return refused
        if any(_ist(r, "bestaetigt") and r.get("message_id") == event.message_id for r in existing):
            return SyncResult("sent", message_id=event.message_id)
        if any(r.get("kind") == "dead_letter" and r.get("message_id") == event.message_id for r in existing):
            return SyncResult("dead_letter", "bereits_fehlgeschlagen", message_id=event.message_id)
        if prior and not force:
            return SyncResult("queued", str(prior.get("reason") or "eingereiht"), int(prior.get("attempts", 0)),
                              event.message_id)
        owner, bad = self._owner(event.source_thread)
        if bad == "owner_mehrdeutig" or bad == "owner_abweichend":
            return self._block(event, bad)
        if owner is None or bad:
            reason = bad or "kein_aktiver_owner"
            self._audit(event, "queued", reason)
            self._queue(event, "out", reason, 0, prior)
            return SyncResult("queued", reason, message_id=event.message_id)
        if not self.sync.attest("owner_lease"):
            return self._block(event, "spiegel_unbelegt")
        payload = {**asdict(event), "status": "gesendet"}
        sender_payload = {**payload, "spiegel": True}
        try:
            # The durable audit is the send precondition: an unrecorded message is never projected.
            self._audit(event, "sent")
        except OSError:
            return SyncResult("blocked", "audit_fehler", message_id=event.message_id)
        try:
            state, ref = self._stage(event, "sender_projection", lambda: self.sync.sender_project(
                owner, {**sender_payload, "egress_key": egress_key(event.conversation_id, event.message_id,
                                                            "sender_projection", event.source_thread)}))
            if state == "busy":
                return SyncResult("queued", "in_bearbeitung", message_id=event.message_id)
            if state == "ambiguous":
                self._audit(event, "blocked", "ausgang_unbestaetigt")
                return self.dead_letter_silent(event, "ausgang_unbestaetigt")
            self.sync.journal.append(event.conversation_id, {
                "kind": "projection", "conversation_id": event.conversation_id, "message_id": event.message_id,
                "sender_projection": ref, "spiegel": True, "status": "gesendet", "masking": event.masking})
            if self.sync.transport is not None:
                state, _ = self._stage(event, "transport", lambda: self.sync.transport(payload) and "" or "ok",
                                       resend_safe=True)
                if state == "busy":
                    return SyncResult("queued", "in_bearbeitung", message_id=event.message_id)
        except Exception as exc:
            if str(exc).startswith("a2a_id_unbelegt"):
                self._audit(event, "Vertragsbruch", "a2a_id_unbelegt")
                return self.dead_letter(event, "a2a_id_unbelegt", 0)
            reason = "target_busy" if "target_busy" in str(exc) else "transport_unavailable"
            attempts = int(prior.get("attempts", 0)) if prior else 0
            attempts += reason != "target_busy"
            if attempts >= MAX_ATTEMPTS:
                return self.dead_letter(event, "retry_erschoepft", attempts)
            self._queue(event, "out", reason, attempts, prior)
            return SyncResult("queued", reason, attempts, event.message_id)
        self.sync.journal.append_once(event.conversation_id, {
            "kind": "bestaetigt", "conversation_id": event.conversation_id, "message_id": event.message_id,
            "spiegel": True, "status": "gesendet", "sender_projection": ref, "masking": event.masking})
        return SyncResult("sent", message_id=event.message_id)

    def dead_letter_silent(self, event: ThreadEnvelope, reason: str) -> SyncResult:
        self.sync.journal.append(event.conversation_id, {
            "kind": "dead_letter", "direction": "out", "conversation_id": event.conversation_id,
            "message_id": event.message_id, "status": "fehlgeschlagen", "reason": reason, "attempts": 0})
        return SyncResult("dead_letter", reason, 0, event.message_id)


class InboundStateMachine(_Machine):
    def receive(self, event: ThreadEnvelope, *, force: bool = False, external_dispatch: bool = False) -> SyncResult:
        """Validate/authenticate BEFORE any persistence, then project under the recipient owner."""
        kind = "external" if external_dispatch else "local"
        reason = self._gate(event, "provider_binding", "tenant", "egress", "pre_session_hook", "audit",
                            *(("a2a_admission",) if event.transport == "a2a" else ()))
        if reason:
            return SyncResult("blocked", reason, message_id=event.message_id)
        if event.art != "gespraech":
            return SyncResult("blocked", "art_unzulaessig", message_id=event.message_id)
        if event.tenant is None or event.tenant != self.sync.auth.tenant:
            return SyncResult("blocked", "tenant_abweichend", message_id=event.message_id)
        if _norm(event.target_thread) != _norm(self.sync.auth.thread):
            return SyncResult("blocked", "owner_abweichend", message_id=event.message_id)
        try:
            proof_ok = verify_masking_proof(event.text, event.masking, secrets=self.sync.current_secrets())
        except ValueError:
            proof_ok = False
        if not proof_ok:
            return self._block(event, "maskierung_unbelegt")
        if event.spiegel:
            return self._block(event, "spiegel_nicht_ausfuehrbar")
        event, refused = self._canonical(event)  # atomic compare-or-create; continue ONLY with the canonical object
        if refused is not None:
            return refused
        existing = self.sync.journal.events(event.conversation_id)
        if any(r.get("kind") == "inbound_processed" and r.get("message_id") == event.message_id for r in existing):
            return SyncResult("duplicate", "bereits_verarbeitet", message_id=event.message_id)
        prior = next((r for r in reversed(existing) if _ist(r, "eingereiht", "versuch") and r.get("direction") == "in"
                      and r.get("message_id") == event.message_id), None)
        owner, bad = self._owner(event.target_thread)
        if bad == "owner_mehrdeutig" or bad == "owner_abweichend":
            return self._block(event, bad)
        if owner is None or bad:
            reason = bad or "kein_aktiver_owner"
            self._queue(event, "in", reason, int(prior.get("attempts", 0)) if prior else 0, prior, dispatch=kind)
            self._audit(event, "queued", reason)
            return SyncResult("queued", reason, message_id=event.message_id)
        if self.sync.project is None or not self.sync.attest("owner_lease"):
            return self._block(event, "spiegel_unbelegt")
        payload = {**asdict(event), "status": "empfangen"}
        try:
            state, ref = self._stage(event, "recipient_projection", lambda: self.sync.project(
                owner, {**payload, "egress_key": egress_key(event.conversation_id, event.message_id,
                                                            "recipient_projection", event.target_thread)}))
            if state == "busy":
                return SyncResult("queued", "in_bearbeitung", message_id=event.message_id)
            if state == "ambiguous":
                return self._block(event, "eingangsprojektion_unbestatigt")
            if self.sync.pre_session_hook is None:
                return self._block(event, "sitzung_unmaskiert")
            if True:  # atomic: exactly one receipt per message even for concurrent exact replays
                self.sync.journal.append_once(event.conversation_id, {
                    "kind": "inbound_receipt", "conversation_id": event.conversation_id,
                    "message_id": event.message_id, "parent_message_id": event.parent_message_id,
                    "recipient_projection": ref, "status": "empfangen",
                    "masking": event.masking})
            if not self.sync.pre_session_hook({**payload, "text": ""}):
                self._queue(event, "in", "eingangsprojektion_unbestatigt", 0, prior, dispatch=kind)
                return SyncResult("queued", "eingangsprojektion_unbestatigt", message_id=event.message_id)
            if external_dispatch:
                # Durable recipient inbox: enqueue the dispatch (PENDING) AND a recovery queue row BEFORE
                # any ticket is returned, so a gateway that is down now still gets the message later.
                j, conv, mid = self.sync.journal, event.conversation_id, event.message_id
                key = dispatch_key(event.tenant, conv, mid, event.recipient)
                j.dispatch_enqueue(conv, mid, key)
                if prior is None:
                    self._queue(event, "in", "dispatch_ausstehend", 0, None, dispatch="external")
                claim = j.claim(conv, mid, "dispatch", token=self.sync.token, now=self.sync.clock(),
                                resend_safe=True)
                if claim["state"] == "done":
                    return SyncResult("duplicate", "bereits_verarbeitet", message_id=mid)
                if claim["state"] == "busy":
                    return SyncResult("queued", "in_bearbeitung", message_id=mid)
                ticket = {"conversation_id": conv, "message_id": mid, "token": self.sync.token,
                          "fence": claim["fence"], "key": key}
                reply = j.reply_status(conv, mid, key, replier=event.recipient)
                state, expires = j.dispatch_info(conv, mid)
                if reply in {"tampered", "unavailable"} or (reply == "valid" and state not in {"REPLIED", "DONE"}):
                    # A durable (or tampered) reply exists: the model is never invoked; the reply flush
                    # finalizes a valid one, a tampered one fails closed.
                    self.sync.abort_dispatch(ticket)
                    return SyncResult("queued", {"valid": "antwort_ausstehend", "tampered": "antwort_manipuliert",
                                                 "unavailable": "speicherschluessel_fehlt"}[reply], message_id=mid)
                if state in {"REPLIED", "DONE"}:
                    # The authenticated reply is durable (only the terminal record is missing): finalize,
                    # never rerun the model, never project the reply again.
                    if self.sync.ack_dispatch(ticket):
                        return SyncResult("duplicate", "bereits_verarbeitet", message_id=mid)
                    self.sync.abort_dispatch(ticket)
                    return SyncResult("queued", "ack_ausstehend", message_id=mid)
                if state == "REPLY_PENDING":
                    # The model already produced its reply (stored, masked). Never re-run it: the reply
                    # flush (fresh authoritative context) finalizes it.
                    self.sync.abort_dispatch(ticket)
                    return SyncResult("queued", "antwort_ausstehend", message_id=mid)
                if state in {"RUNNING", "ACCEPTED", "COMPLETED"} and expires > self.sync.clock():
                    # SCHEDULED is NOT completed: a run may still be in flight. Not terminal, not resubmitted.
                    self.sync.abort_dispatch(ticket)
                    return SyncResult("queued", "in_bearbeitung", message_id=mid)
                # PENDING / RELEASED / COMPLETED-without-durable-reply / SCHEDULED-or-RUNNING with an expired
                # lease (the process died before the reply was durable): (re)submit with the SAME dispatch key; the model may run again,
                # visible projections stay deduplicated by their stable keys.
                return SyncResult("admitted", message_id=mid, ticket=ticket)
            if self.sync.process is not None:
                state, _ = self._stage(event, "process", lambda: self.sync.process(payload) and "" or "ok")
                if state in {"busy", "ambiguous"}:
                    return SyncResult("queued" if state == "busy" else "blocked", f"verarbeitung_{state}",
                                      message_id=event.message_id)
        except Exception:
            self._queue(event, "in", "eingangsprojektion_unbestatigt",
                        (int(prior.get("attempts", 0)) if prior else 0) + 1, prior, dispatch=kind)
            return SyncResult("queued", "eingangsprojektion_unbestatigt", message_id=event.message_id)
        self.sync.journal.append_once(event.conversation_id, {
            "kind": "inbound_processed", "conversation_id": event.conversation_id, "message_id": event.message_id,
            "status": "empfangen", "masking": event.masking})
        self._audit(event, "received")
        return SyncResult("received", message_id=event.message_id)


class ThreadSync:
    def __init__(self, *, journal: Journal, auth: GatewayAuthContext,
                 owner_resolver: Callable[[dict[str, Any]], Owner | list[Owner] | None],
                 sender_project: Callable[[Owner, dict[str, Any]], str] | None = None,
                 sender_edit: Callable[[Owner, str, dict[str, Any]], dict[str, Any]] | None = None,
                 project: Callable[[Owner, dict[str, Any]], str] | None = None,
                 transport: Callable[[dict[str, Any]], Any] | None = None,
                 secrets: Iterable[str] = (), secrets_provider: Callable[[], Iterable[str]] | None = None,
                 pre_session_hook: Callable[[dict[str, Any]], bool] | None = None,
                 process: Callable[[dict[str, Any]], Any] | None = None,
                 evidence: EvidenceRegistry | None = None, clock: Callable[[], float] = time.time,
                 dispatcher: Callable[..., Any] | None = None,
                 dispatchers: dict[str, Callable[..., Any]] | None = None,
                 dispatch_gate: Callable[[ThreadEnvelope], Any] | None = None,
                 authority: Callable[[], bool] | None = None):
        self.journal, self.auth, self.owner_resolver = journal, auth, owner_resolver
        self.sender_project, self.sender_edit, self.project, self.transport = sender_project, sender_edit, project, transport
        self._secrets, self._secrets_provider = tuple(secrets), secrets_provider
        self.pre_session_hook, self.process, self.clock = pre_session_hook, process, clock
        # Gateway hand-off for externally dispatched messages recovered from the queue (no live request).
        self.dispatcher = dispatcher
        self.dispatchers = dict(dispatchers or {})  # per transport: a2a | message_agent
        self.dispatch_gate = dispatch_gate or (lambda _event: contextlib.nullcontext())
        self.authority = authority  # live-grant check; revocation/expiry fail every gated operation
        self.evidence = evidence if evidence is not None else load_evidence_registry()
        self.evidence.bind(instance=auth.runtime_instance, owner_token=auth.owner_token, turn=auth.turn_id)
        self.token = f"{auth.runtime_instance}:{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex[:8]}"
        self.outbound, self.inbound = OutboundStateMachine(self), InboundStateMachine(self)

    def current_secrets(self) -> tuple[str, ...]:
        extra = tuple(self._secrets_provider()) if self._secrets_provider else ()
        if self.authority is not None and not self.authority():
            raise AuthorityLost("autoritaet_widerrufen")  # re-validate after the untrusted callback
        return self._secrets + extra

    def attest(self, *names: str) -> bool:
        return all([self.evidence.attest(name) for name in names])

    def send(self, envelope: ThreadEnvelope) -> SyncResult:
        try:
            return self.outbound.send(envelope)
        except AuthorityLost:
            return SyncResult("blocked", "autoritaet_widerrufen", message_id=envelope.message_id)

    def receive(self, envelope: ThreadEnvelope, *, external_dispatch: bool = False) -> SyncResult:
        try:
            return self.inbound.receive(envelope, external_dispatch=external_dispatch)
        except AuthorityLost:
            return SyncResult("blocked", "autoritaet_widerrufen", message_id=envelope.message_id)

    def update_status(self, envelope: ThreadEnvelope, status: str, *, reason: str = "") -> SyncResult:
        try:
            return self.outbound.update_status(envelope, status, reason=reason)
        except AuthorityLost:
            return SyncResult("blocked", "autoritaet_widerrufen", message_id=envelope.message_id)

    # --- post-dispatch seam for externally dispatched inbound messages -------------------
    def _ticket_mark(self, kind: str, ticket: dict[str, Any]) -> bool:
        return self.journal.mark(ticket["conversation_id"], kind, ticket["message_id"], "dispatch",
                                 token=ticket["token"], fence=int(ticket["fence"]))

    def dispatch_started(self, ticket: dict[str, Any]) -> bool:
        """Last step before handing the message to the model. Fenced-out callers get False."""
        return self._ticket_mark("stage_intent", ticket)

    def _dispatch_move(self, kind: str, ticket: dict[str, Any], expect: set[str], **extra: Any) -> bool:
        return self.journal.dispatch_transition(
            ticket["conversation_id"], ticket["message_id"], kind, expect=expect, token=ticket["token"],
            fence=int(ticket["fence"]), key=str(ticket.get("key", "")), **extra)

    def dispatch_begin(self, ticket: dict[str, Any]) -> bool:
        """Gateway-side atomic claim PENDING -> RUNNING, taken BEFORE the model is invoked. Only the
        current fenced claimant can take it, and only once: a RUNNING record is never submitted again."""
        return self._dispatch_move("dispatch_running", ticket, {"PENDING", "RELEASED"},
                                   now=self.clock(), lease=CLAIM_LEASE_SECONDS, resubmit_expired=True,
                                   replier=self.auth.profile)

    def accept_dispatch(self, ticket: dict[str, Any]) -> bool:
        """The gateway SCHEDULED the event (RUNNING -> ACCEPTED). Not completion."""
        return self._dispatch_move("dispatch_accepted", ticket, {"RUNNING"},
                                   now=self.clock(), lease=COMPLETION_LEASE_SECONDS)

    def complete_model(self, ticket: dict[str, Any]) -> bool:
        """MODEL_COMPLETED (nonterminal)."""
        return self.journal.dispatch_mark_completed(ticket["conversation_id"], ticket["message_id"],
                                                    str(ticket.get("key", "")), now=self.clock())

    def mark_reply_pending(self, ticket: dict[str, Any]) -> bool:
        return self.journal.dispatch_mark_reply_pending(ticket["conversation_id"], ticket["message_id"],
                                                        str(ticket.get("key", "")))

    def mark_reply_stored(self, ticket: dict[str, Any], *, no_reply: bool = False) -> bool:
        return self.journal.dispatch_mark_replied(ticket["conversation_id"], ticket["message_id"],
                                                  str(ticket.get("key", "")), no_reply=no_reply)

    def finalize_turn(self, ticket: dict[str, Any]) -> bool:
        """TURN_FINALIZED: the single terminal record, allowed ONLY once the reply is durable."""
        event = self.journal.load_projection(ticket["conversation_id"], ticket["message_id"])
        if not self.journal.complete_dispatch(ticket["conversation_id"], ticket["message_id"],
                                              token=str(ticket.get("token", "")), fence=int(ticket.get("fence", 0)),
                                              masking=event.masking, key=str(ticket.get("key", "")),
                                              require_replied=True):
            return False
        self.inbound._audit(event, "received")
        return True

    def finish_dispatch(self, ticket: dict[str, Any], outcome: str = "completed",
                        reply_expected: bool = True) -> bool:
        """Gateway completion callback target. A completed run is only MODEL_COMPLETED (nonterminal): the
        turn is finalized after its reply is durable. `reply_expected=False` is the typed, intentional
        no-reply outcome (the run ended without producing any reply)."""
        if outcome != "completed":
            return False  # failed / cancelled / interrupted: stays recoverable, no reply
        if not self.complete_model(ticket):
            return False
        if reply_expected:
            return True
        return self.mark_reply_stored(ticket, no_reply=True) and self.finalize_turn(ticket)

    def release_dispatch(self, ticket: dict[str, Any]) -> bool:
        """The gateway definitively refused it, so the model never started: RUNNING -> RELEASED."""
        return self._dispatch_move("dispatch_released", ticket, {"RUNNING"})

    def dispatch_admitted(self, event: ThreadEnvelope, ticket: dict[str, Any]) -> SyncResult:
        """Hand an admitted message to the recipient dispatcher for ITS transport (a2a / message_agent).
        A missing dispatcher fails closed: the row stays queued, nothing is marked processed."""
        return self._dispatch_recovered(event, ticket)

    def _dispatch_recovered(self, event: ThreadEnvelope, ticket: dict[str, Any]) -> SyncResult:
        """begin (durable RUNNING) -> recipient dispatcher -> SCHEDULED -> MODEL_COMPLETED -> terminal.

        A dispatcher taking ``(envelope, complete)`` is asynchronous: it only SCHEDULES the run and calls
        ``complete(outcome)`` when the run actually ends, so the row stays nonterminal until then. A
        one-argument dispatcher executes synchronously: its return is the completion."""
        mid = event.message_id
        fn = self.dispatchers.get(event.transport) or self.dispatcher
        if fn is None:
            self.abort_dispatch(ticket)
            return SyncResult("queued", "kein_dispatcher", message_id=mid)
        if not self.dispatch_begin(ticket):
            self.abort_dispatch(ticket)
            return SyncResult("queued", "dispatch_nicht_beginnbar", message_id=mid)
        import inspect
        try:
            asynchronous = len([p for p in inspect.signature(fn).parameters.values()
                                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]) >= 2
        except (TypeError, ValueError):
            asynchronous = False
        with self.dispatch_gate(event):
            try:
                taken = fn(event, lambda outcome="completed", reply_expected=True:
                       self.finish_dispatch(ticket, outcome, reply_expected)) \
                    if asynchronous else fn(event)  # True accepted / False refused / None outcome unknown
            except Exception:
                taken = False
            if taken == "reply_pending":
                self.abort_dispatch(ticket)  # reply stored durably; finalization retried with a fresh context
                return SyncResult("queued", "antwort_ausstehend", message_id=mid)
            if taken is None:
                self.abort_dispatch(ticket)  # stays RUNNING: re-driven after the lease
                return SyncResult("queued", "gateway_unbestaetigt", message_id=mid)
            if not taken:
                self.release_dispatch(ticket)
                self.abort_dispatch(ticket)
                return SyncResult("queued", "gateway_abgelehnt", message_id=mid)
            self.accept_dispatch(ticket)
            if asynchronous:
                self.abort_dispatch(ticket)  # free the claim; completion arrives via the callback
                return SyncResult("queued", "modell_geplant", message_id=mid)
            self.complete_model(ticket)
            self.mark_reply_stored(ticket)  # a synchronous dispatcher's return = reply durable or intentionally none
            if not self.ack_dispatch(ticket):
                self.abort_dispatch(ticket)  # MODEL_COMPLETED is durable: the next pass finalizes, never reruns
                return SyncResult("queued", "ack_ausstehend", message_id=mid)
            return SyncResult("received", message_id=mid)

    def ack_dispatch(self, ticket: dict[str, Any]) -> bool:
        """Finalize ThreadSync with ONE atomic terminal record (see Journal.complete_dispatch)."""
        event = self.journal.load_projection(ticket["conversation_id"], ticket["message_id"])
        if not self.journal.complete_dispatch(ticket["conversation_id"], ticket["message_id"],
                                              token=ticket["token"], fence=int(ticket["fence"]),
                                              masking=event.masking, key=str(ticket.get("key", ""))):
            return False
        self.inbound._audit(event, "received")  # informational; the terminal record is already durable
        return True

    def abort_dispatch(self, ticket: dict[str, Any]) -> None:
        """Release this claimant's claim (the durable dispatch record is untouched)."""
        self._ticket_mark("stage_failed", ticket)

    def retry_due(self, *, now: float | None = None) -> list[SyncResult]:
        """Recover queue rows from the journal (outbound and inbound); owners are re-resolved."""
        original = self.clock
        if now is not None:
            self.clock = (lambda t=now: t)
        try:
            return self._retry_due(self.clock())
        finally:
            self.clock = original

    def _retry_due(self, now: float) -> list[SyncResult]:
        results: list[SyncResult] = []
        for conv in self.journal.conversations():
            try:
                rows = self.journal.events(conv)
            except ValueError:
                continue
            terminal = {r.get("message_id") for r in rows
                        if _ist(r, "bestaetigt") or r.get("kind") in {"dead_letter", "inbound_processed"}}
            latest = {str(r["message_id"]): r for r in rows
                      if _ist(r, "eingereiht", "versuch") and r.get("message_id") not in terminal}
            for message_id, row in latest.items():
                if float(row.get("next_at", now + 1)) > now:
                    continue
                try:
                    event = self.journal.load_projection(conv, message_id)
                except (ValueError, OSError):
                    continue
                attempts = int(row.get("attempts", 0))
                direction = row.get("direction", "out")
                expired = now - float(row.get("enqueued_at", now)) >= TTL_SECONDS
                if expired or attempts >= MAX_ATTEMPTS:
                    why = "ttl_abgelaufen" if expired else "retry_erschoepft"
                    if direction == "out":
                        results.append(self.outbound.dead_letter(event, why, attempts))
                    else:
                        self.journal.append(conv, {"kind": "dead_letter", "direction": "in", "conversation_id": conv,
                                                  "message_id": message_id, "status": "fehlgeschlagen",
                                                  "reason": why, "attempts": attempts})
                        results.append(SyncResult("dead_letter", why, attempts, message_id))
                else:
                    if direction == "out":
                        results.append(self.outbound.send(event, force=True, canonical=True))
                        continue
                    external = row.get("dispatch") == "external"  # preserved across restarts
                    result = self.inbound.receive(event, force=True, external_dispatch=external)
                    if result.status == "admitted":
                        result = self._dispatch_recovered(event, result.ticket)
                    results.append(result)
        return results

    def next_due_at(self) -> float | None:
        """Earliest scheduled retry among non-terminal queue rows (None when nothing is queued)."""
        due: list[float] = []
        for conv in self.journal.conversations():
            try:
                rows = self.journal.events(conv)
            except ValueError:
                continue
            terminal = {r.get("message_id") for r in rows
                        if _ist(r, "bestaetigt") or r.get("kind") in {"dead_letter", "inbound_processed"}}
            latest = {str(r["message_id"]): r for r in rows
                      if _ist(r, "eingereiht", "versuch") and r.get("message_id") not in terminal}
            due.extend(float(r.get("next_at", 0)) for r in latest.values())
        return min(due) if due else None

    def audit(self, conversation_id: str) -> list[dict[str, Any]]:
        return [e for e in self.journal.events(conversation_id) if e.get("kind") == "audit"]


if __name__ == "__main__":  # python -m tools.bot_thread_sync  → regenerate the shipped evidence entries
    print(write_evidence_registry())
