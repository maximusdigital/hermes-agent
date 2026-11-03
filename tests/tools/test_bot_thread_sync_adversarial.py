"""Directory-swap attacks: every journal/relay operation is pinned, never re-resolved by path."""
import os

import pytest

from tools import bot_relay, pinned_fs
from tools.bot_thread_sync import Journal
from tests.tools.bot_thread_support import envelope, make_sync


def test_conversation_dir_swapped_for_symlink_is_refused(tmp_path):
    journal = Journal(tmp_path / "home" / "journal", trusted_base=tmp_path / "home")
    journal.append("conv", {"kind": "audit"})
    outside = tmp_path / "outside"; outside.mkdir()
    (tmp_path / "home" / "journal" / "conv").rename(tmp_path / "home" / "journal" / "moved")
    (tmp_path / "home" / "journal" / "conv").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        journal.append("conv", {"kind": "audit"})
    assert list(outside.iterdir()) == []


def test_projection_dir_swapped_for_symlink_is_refused(tmp_path):
    sync = make_sync(tmp_path, owner_resolver=lambda t: None, sender_project=lambda *_: "x")
    sync.send(envelope())
    proj = tmp_path / "a" / "journal" / "conv-1" / "projections"
    outside = tmp_path / "outside"; outside.mkdir()
    proj.rename(proj.with_name("old"))
    proj.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        sync.journal.load_projection("conv-1", "msg-1")
    with pytest.raises(ValueError):
        sync.journal.save_projection(envelope(message_id="msg-2"))
    assert list(outside.iterdir()) == []


def test_file_symlink_swap_is_refused_on_read_and_write(tmp_path):
    fd = pinned_fs.open_chain(tmp_path, ("d",))
    secret = tmp_path / "secret"; secret.write_text("S")
    os.symlink(secret, "link", dir_fd=fd)
    with pytest.raises(ValueError):
        pinned_fs.read_bytes(fd, "link")
    with pytest.raises(OSError):
        pinned_fs.append_bytes(fd, "link", b"x")
    assert secret.read_text() == "S"
    os.close(fd)


def test_relay_payload_and_reply_dirs_swapped_for_symlinks_are_refused(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    base = bot_relay.relay_root(root); base.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    for sub in (bot_relay.PAYLOADS_DIR, bot_relay.REPLIES_DIR):
        (base / sub).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        bot_relay._payload_write(root, "a.json", {"id": "a"})
    with pytest.raises(ValueError):
        bot_relay._payload_write(root, "a.json", {"id": "a"}, subdir=bot_relay.REPLIES_DIR)
    with pytest.raises(ValueError):
        bot_relay.resolve_payload(root, "a" * 32, expected_digest="x")
    assert list(outside.iterdir()) == []
