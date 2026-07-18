"""
Unit test for orchestrator/daytona_client.py's get_sandbox_info.

Phase 3A verified the rest of this module against real Daytona sandboxes
(5/5 integration tests, not part of this pytest suite — see ROADMAP.md).
This file covers only get_sandbox_info, added in Phase 5, with the SDK
client mocked so no real credentials or network access are required.
"""

from unittest.mock import MagicMock, patch

from orchestrator import daytona_client


def test_get_sandbox_info_reads_expected_fields():
    fake_sandbox = MagicMock()
    fake_sandbox.target = "us-east-1"
    fake_sandbox.created_at = "2026-07-18T14:32:01Z"
    fake_sandbox.cpu = 2
    fake_sandbox.memory = 4

    fake_client = MagicMock()
    fake_client.get.return_value = fake_sandbox

    with patch.object(daytona_client, "_get_client", return_value=fake_client):
        info = daytona_client.get_sandbox_info("sbox-abc123")

    assert info == {
        "region": "us-east-1",
        "created_at": "2026-07-18T14:32:01Z",
        "cpu": 2,
        "memory": 4,
    }
    fake_client.get.assert_called_once_with("sbox-abc123")
