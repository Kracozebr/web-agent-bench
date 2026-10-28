from __future__ import annotations

import unittest

from .benchmark_run_lifecycle_verifier import _derive_023


class BenchmarkRunLifecycleVerifierTests(unittest.TestCase):
    def test_server_worker_preparation_does_not_mean_hosted_model_execution(self):
        intent_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        capture = {
            "cases": {
                "seed": {"intent": {"id": intent_id, "task_ids": ["M1"]}},
                "acceptance": {
                    "after": {
                        "database": {
                            "intents": [{"id": intent_id, "status": "accepted", "run_id": run_id}],
                            "runs": [{"id": run_id, "intent_id": intent_id,
                                "status": "preparing", "started_at": "2026-10-28T12:00:02Z"}],
                            "actions": [], "publicActionMarkers": [], "rankedBestResults": [],
                        },
                    },
                    "attempts": {"primaryMcp": {"clientModel": {
                        "externalModelCalls": 0, "llmBenchmarkInvocation": False,
                    }}},
                },
            },
        }

        facts = _derive_023(capture)

        self.assertTrue(facts["no_card_publication_or_model_execution"])


if __name__ == "__main__":
    unittest.main()
