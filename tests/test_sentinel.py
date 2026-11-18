"""Offline tests for HA Reddit Sentinel.

No network, no Reddit credentials: Reddit posts are faked with simple
namespaces and the Home Assistant HTTP calls are captured.
Run with:  python -m unittest discover -s tests -v
"""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sentinel

INVENTORY = ["Home Assistant", "Zigbee2MQTT", "Jellyfin"]
KEYWORDS = ["security", "vulnerability", "breaking change", "critical update"]


def fake_post(**overrides):
    post = SimpleNamespace(
        id="abc123",
        title="",
        selftext="",
        subreddit="homeassistant",
        permalink="/r/homeassistant/comments/abc123/x/",
        author="someuser",
        created_utc=1795000000.0,
    )
    for key, value in overrides.items():
        setattr(post, key, value)
    return post


class MatchTests(unittest.TestCase):
    def test_inventory_and_keyword_matches(self):
        m = sentinel.match_post(
            "Home Assistant 2026.11 fixes a critical security issue", "",
            INVENTORY, KEYWORDS)
        self.assertIsNotNone(m)
        self.assertEqual(m["inventory"], "Home Assistant")

    def test_inventory_alone_does_not_match(self):
        m = sentinel.match_post(
            "Show me your Home Assistant dashboards!", "",
            INVENTORY, KEYWORDS)
        self.assertIsNone(m)

    def test_cve_without_keyword_matches(self):
        m = sentinel.match_post(
            "Zigbee2MQTT users should read about CVE-2026-12345", "",
            INVENTORY, KEYWORDS)
        self.assertIsNotNone(m)
        self.assertEqual(m["cves"], ["CVE-2026-12345"])

    def test_unrelated_post_does_not_match(self):
        m = sentinel.match_post(
            "Critical update for my sourdough starter", "",
            INVENTORY, KEYWORDS)
        self.assertIsNone(m)

    def test_body_is_searched_too(self):
        m = sentinel.match_post(
            "PSA for everyone", "This vulnerability affects Jellyfin servers.",
            INVENTORY, KEYWORDS)
        self.assertIsNotNone(m)


class StoreTests(unittest.TestCase):
    def test_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = sentinel.AlertStore(Path(tmp) / "test.db")
            self.assertTrue(store.is_empty())
            match = {"inventory": "Jellyfin", "keyword": "security", "cves": []}
            post = fake_post(title="Jellyfin security release")
            self.assertTrue(store.record(post, match, notified=True))
            self.assertFalse(store.record(post, match, notified=True))
            self.assertFalse(store.is_empty())


class NotifyTests(unittest.TestCase):
    def test_notification_payloads(self):
        cfg = {
            "home_assistant": {
                "url": "http://ha.local:8123",
                "token": "TOKEN",
                "notify_service": "notify.mobile_app_phone",
            }
        }
        post = fake_post(title="Jellyfin security release")
        match = {"inventory": "Jellyfin", "keyword": "security", "cves": []}
        with mock.patch.object(sentinel.requests, "post") as mock_post:
            mock_post.return_value.raise_for_status = lambda: None
            sentinel.notify_home_assistant(cfg, post, match)
        # persistent_notification + mobile notify
        self.assertEqual(mock_post.call_count, 2)
        urls = [call.args[0] for call in mock_post.call_args_list]
        self.assertIn("http://ha.local:8123/api/services/persistent_notification/create", urls)
        self.assertIn("http://ha.local:8123/api/services/notify/mobile_app_phone", urls)


class RunOnceTests(unittest.TestCase):
    def _cfg(self):
        return {
            "polling": {"subreddits": ["homeassistant"], "interval_minutes": 30},
            "inventory": INVENTORY,
            "alert_keywords": KEYWORDS,
            "home_assistant": {
                "url": "http://ha.local:8123",
                "token": "TOKEN",
                "notify_service": "",
            },
        }

    def test_end_to_end_with_fake_reddit(self):
        posts = [
            fake_post(id="p1", title="Home Assistant security advisory"),
            fake_post(id="p2", title="My new dashboard, what do you think?"),
            fake_post(id="p3", title="Jellyfin breaking change in 10.11"),
        ]
        subreddit = SimpleNamespace(new=lambda limit: posts)
        reddit = SimpleNamespace(subreddit=lambda name: subreddit)
        with tempfile.TemporaryDirectory() as tmp:
            store = sentinel.AlertStore(Path(tmp) / "test.db")
            with mock.patch.object(sentinel, "notify_home_assistant") as notify:
                # First pass as a normal (non-seed) run: 2 alerts expected.
                n = sentinel.run_once(reddit, self._cfg(), store, seed=False)
                self.assertEqual(n, 2)
                self.assertEqual(notify.call_count, 2)
                # Second pass: everything is already known, no new alert.
                n = sentinel.run_once(reddit, self._cfg(), store, seed=False)
                self.assertEqual(n, 0)
                self.assertEqual(notify.call_count, 2)


if __name__ == "__main__":
    unittest.main()
