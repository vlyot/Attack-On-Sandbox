"""
Tests for orchestrator/setup.py.

start_sandbox itself is already covered by test_main.py; this file only
covers setup.main()'s own responsibility — persisting the sandbox ID to
disk and printing the URL — with start_sandbox mocked out.
"""

from unittest.mock import patch

from orchestrator import setup


def test_setup_writes_sandbox_id_file(tmp_path, monkeypatch, capsys):
    sandbox_id_file = tmp_path / ".sandbox_id"
    monkeypatch.setattr(setup, "SANDBOX_ID_PATH", sandbox_id_file)

    with patch.object(
        setup, "start_sandbox", return_value=("sbox-abc123", "https://sbox-abc123.daytonaproxy01.net")
    ) as fake_start:
        setup.main()

    fake_start.assert_called_once()
    assert sandbox_id_file.read_text(encoding="utf-8") == "sbox-abc123"

    captured = capsys.readouterr()
    assert "sbox-abc123" in captured.out
    assert "https://sbox-abc123.daytonaproxy01.net" in captured.out
