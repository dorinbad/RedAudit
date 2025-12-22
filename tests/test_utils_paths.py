#!/usr/bin/env python3
"""
Tests for path resolution helpers.
"""

from pathlib import Path

import os

from redaudit.utils import paths


def test_get_invoking_user_non_root(monkeypatch):
    monkeypatch.setattr(paths, "_is_root", lambda: False)
    assert paths.get_invoking_user() is None


def test_get_invoking_user_from_sudo(monkeypatch):
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    monkeypatch.setenv("SUDO_USER", "alice")
    assert paths.get_invoking_user() == "alice"


def test_expand_user_path_uses_invoking_home(monkeypatch):
    monkeypatch.setattr(paths, "get_invoking_user", lambda: "alice")
    monkeypatch.setattr(paths, "get_invoking_home_dir", lambda: "/home/alice")
    assert paths.expand_user_path("~/Reports") == "/home/alice/Reports"
    assert paths.expand_user_path("~") == "/home/alice"


def test_expand_user_path_passthrough():
    assert paths.expand_user_path(" /tmp ") == "/tmp"


def test_read_xdg_documents_dir_parses(tmp_path):
    config_dir = tmp_path / ".config"
    config_dir.mkdir()
    user_dirs = config_dir / "user-dirs.dirs"
    user_dirs.write_text('XDG_DOCUMENTS_DIR="$HOME/My Docs"\n', encoding="utf-8")

    result = paths._read_xdg_documents_dir(str(tmp_path))
    assert result == str(tmp_path / "My Docs")


def test_get_documents_dir_prefers_documentos(tmp_path, monkeypatch):
    documentos = tmp_path / "Documentos"
    documentos.mkdir()
    monkeypatch.setattr(paths, "get_reports_home_dir", lambda: str(tmp_path))
    assert paths.get_documents_dir() == str(documentos)


def test_get_documents_dir_defaults_documents(tmp_path, monkeypatch):
    documents = tmp_path / "Documents"
    documents.mkdir()
    monkeypatch.setattr(paths, "get_reports_home_dir", lambda: str(tmp_path))
    assert paths.get_documents_dir() == str(documents)


def test_resolve_invoking_user_owner_from_env(monkeypatch):
    monkeypatch.setattr(paths, "_is_root", lambda: True)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_GID", "1002")
    assert paths.resolve_invoking_user_owner() == (1001, 1002)


def test_maybe_chown_no_owner(monkeypatch):
    monkeypatch.setattr(paths, "resolve_invoking_user_owner", lambda: None)
    paths.maybe_chown_to_invoking_user("/tmp/nope")


def test_maybe_chown_tree_no_owner(monkeypatch):
    monkeypatch.setattr(paths, "resolve_invoking_user_owner", lambda: None)
    paths.maybe_chown_tree_to_invoking_user("/tmp/nope")


def test_maybe_chown_tree_calls_chown(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    file_path = root / "sub" / "a.txt"
    file_path.write_text("data", encoding="utf-8")

    calls = []

    monkeypatch.setattr(paths, "resolve_invoking_user_owner", lambda: (1001, 1002))
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))

    paths.maybe_chown_tree_to_invoking_user(str(root))
    assert any(str(root) == call[0] for call in calls)


def test_get_reports_home_dir_prefers_invoking(monkeypatch):
    monkeypatch.setattr(paths, "get_invoking_user", lambda: "alice")
    monkeypatch.setattr(paths, "_resolve_home_dir_for_user", lambda _: "/home/alice")
    assert paths.get_reports_home_dir() == "/home/alice"


def test_get_reports_home_dir_fallback(monkeypatch):
    monkeypatch.setattr(paths, "get_invoking_user", lambda: None)
    monkeypatch.setattr(paths, "_get_preferred_human_home_under_home", lambda: "/home/kali")
    assert paths.get_reports_home_dir() == "/home/kali"


def test_get_reports_home_dir_expands_user(monkeypatch):
    monkeypatch.setattr(paths, "get_invoking_user", lambda: None)
    monkeypatch.setattr(paths, "_get_preferred_human_home_under_home", lambda: None)
    monkeypatch.setattr(os.path, "expanduser", lambda _: "/home/default")
    assert paths.get_reports_home_dir() == "/home/default"
