from tools.bot_thread_sync import load_evidence_registry


def test_shipped_registry_is_revision_bound_and_fail_closed():
    registry = load_evidence_registry()
    assert registry.revision != "unproven"
    assert registry.entries
    # Hash/line/seam verification happens inside the loader against this checkout;
    # the shipped entries remain unproven until authenticated runtime callbacks exist.
    assert all(registry.proven(name) is False for name in registry.entries)


def test_registry_rejects_line_or_hash_drift(tmp_path):
    registry = load_evidence_registry()
    name, entry = next(iter(registry.entries.items()))
    drifted = dict(entry, sha256="0" * 64)
    from tools.bot_thread_sync import EvidenceRegistry
    checked = EvidenceRegistry(registry.revision, {name: drifted}, repo_root=registry.repo_root)
    assert checked.proven(name) is False


def test_registry_identity_is_build_artifact_not_vcs_commit(monkeypatch):
    import subprocess
    from tools import bot_thread_sync as m
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("git consulted")))
    registry = m.load_evidence_registry()
    assert registry.revision.startswith("artifact:")  # not "stale"/"unproven": matches this checkout's seams
    assert registry.revision == m.artifact_revision(registry.repo_root)


def test_registry_for_a_different_artifact_is_stale(tmp_path):
    import json, shutil
    from tools import bot_thread_sync as m
    src = m.Path(m.__file__).with_name("bot_thread_evidence.json")
    raw = json.loads(src.read_text())
    raw["revision"] = "artifact:" + "0" * 64
    (tmp_path / "e.json").write_text(json.dumps(raw))
    # copy the repo layout the loader derives its root from
    root = tmp_path / "repo"; (root / "tools").mkdir(parents=True)
    shutil.copy(tmp_path / "e.json", root / "tools" / "bot_thread_evidence.json")
    for rel, _seam in m.SEAMS.values():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(m.Path(m.__file__).parent.parent / rel, root / rel)
    assert m.load_evidence_registry(root / "tools" / "bot_thread_evidence.json").revision == "stale"
