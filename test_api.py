"""End-to-end tests through the Flask API: fire events, walk the audit
chain, exercise the Discernment Key gate on both places it applies.

Run with:  python -m unittest discover -s tests
"""
import os
import tempfile
import unittest

from app import create_app, db as arachnode_db
from seed import seed as seed_db


class TestConfig:
    SIGNING_SECRET = "test-signing-secret"
    DISCERNMENT_KEY = "test-discernment-key"
    TESTING = True
    DEBUG = True
    DATABASE_PATH = None  # set per-test in setUp


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.db_path = path
        TestConfig.DATABASE_PATH = path

        self.app = create_app(config_object=TestConfig)
        seed_db(self.app)
        self.client = self.app.test_client()

    def tearDown(self):
        os.remove(self.db_path)


class TestHealthAndPolicies(ApiTestCase):
    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "armed")

    def test_list_policies_filtered_by_domain(self):
        resp = self.client.get("/policies?domain=access")
        names = {p["name"] for p in resp.get_json()}
        self.assertIn("Allow employees on internal resources", names)
        self.assertNotIn("Capture on high-confidence beaconing", names)


class TestEventsAndChain(ApiTestCase):
    def test_fire_event_quarantines_and_chains(self):
        resp = self.client.post("/events", json={
            "domain": "threat", "payload": {"agent": {"tool_calls_per_min": 340}},
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["action"], "quarantine")

        chain = self.client.get("/audit-chain").get_json()
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["action"], "quarantine")

        q = self.client.get("/quarantine").get_json()
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0]["status"], "quarantined")

    def test_verify_chain_ok_then_detects_rewrite(self):
        self.client.post("/events", json={
            "domain": "access",
            "payload": {"actor": {"role": "contractor"}, "resource": {"classification": "restricted"}},
        })
        self.assertTrue(self.client.post("/audit-chain/verify").get_json()["verified"])

        # Directly corrupt a block's content without touching its stored
        # hash — the same "rewritten record" the console demo simulates.
        with self.app.app_context():
            conn = arachnode_db.get_db()
            conn.execute("UPDATE audit_blocks SET explanation = 'nothing to see here' WHERE idx = 1")
            conn.commit()

        result = self.client.post("/audit-chain/verify").get_json()
        self.assertFalse(result["verified"])
        self.assertEqual(result["broken_at"], 1)


class TestDiscernmentGate(ApiTestCase):
    def test_release_from_quarantine_requires_discernment_key(self):
        self.client.post("/events", json={
            "domain": "threat", "payload": {"agent": {"tool_calls_per_min": 340}},
        })
        item_id = self.client.get("/quarantine").get_json()[0]["id"]

        denied = self.client.post(f"/quarantine/{item_id}/release")
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.post(
            f"/quarantine/{item_id}/release",
            headers={"X-Discernment-Key": "test-discernment-key"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json()["status"], "released")

    def test_setting_policy_to_allow_requires_discernment_key(self):
        denied = self.client.patch("/policies/p-access-deny", json={"action": "allow"})
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.patch(
            "/policies/p-access-deny", json={"action": "allow"},
            headers={"X-Discernment-Key": "test-discernment-key"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json()["action"], "allow")

    def test_tightening_a_policy_needs_no_discernment_key(self):
        resp = self.client.patch("/policies/p-access-allow", json={"action": "deny"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["action"], "deny")


class TestRogueEditDetection(ApiTestCase):
    def test_rogue_edit_is_caught_on_next_evaluation(self):
        resp = self.client.post("/admin/rogue-edit/p-access-allow", json={"action": "deny"})
        self.assertEqual(resp.status_code, 200)

        fired = self.client.post("/events", json={
            "domain": "access",
            "payload": {"actor": {"role": "employee"}, "resource": {"classification": "internal"}},
        })
        body = fired.get_json()
        self.assertIn("p-access-allow", body["tampered"])
        self.assertEqual(body["action"], "deny")  # falls back to domain default
        self.assertEqual(len(body["alerts"]), 1)

        chain = self.client.get("/audit-chain").get_json()
        self.assertEqual(chain[-1]["kind"], "alert")


if __name__ == "__main__":
    unittest.main()
