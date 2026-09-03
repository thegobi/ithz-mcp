import unittest

from ithz_mcp.native_archive_store import _validate_append_only_events, _validate_new_event_payload


class NativeArchiveStoreValidationTests(unittest.TestCase):
    def test_historical_diagnostic_command_metadata_does_not_block_append_only_validation(self):
        event = {
            "event_id": "evt_005897",
            "kind": "note",
            "source": "end_task_checkpoint",
            "tags": ["checkpoint"],
            "text": "Task checkpoint: safe summary text.",
            "metadata": {
                "commands": [
                    "checkpoint failed with append_only_event_log_invalid:secret_like_event_payload:evt_005897",
                ],
            },
            "semantic_event_hash": "abc123",
        }

        self.assertEqual(_validate_append_only_events([event]), [])

    def test_new_event_metadata_secret_value_is_blocked(self):
        event = {
            "event_id": "evt_000001",
            "kind": "note",
            "source": "test",
            "tags": [],
            "text": "Safe event text.",
            "metadata": {"api_key": "should_not_store_in_memory"},
        }

        with self.assertRaisesRegex(ValueError, "secret_like_event_payload_blocked"):
            _validate_new_event_payload(event)

    def test_historical_event_text_secret_still_blocks(self):
        event = {
            "event_id": "evt_000001",
            "kind": "note",
            "source": "test",
            "tags": [],
            "text": "api_key = should_not_store_in_memory",
            "semantic_event_hash": "abc123",
        }

        self.assertEqual(_validate_append_only_events([event]), ["secret_like_event_text:evt_000001"])


if __name__ == "__main__":
    unittest.main()
