import json
import threading
import time
import unittest
from http.server import HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from zagora.registry import (
    RegistryError,
    registry_get,
    registry_history_add,
    registry_history_list,
    registry_ls,
    registry_register,
    registry_remove,
)
from zagora.server import HealthChecker, HistoryStore, SessionStore, _make_handler


def _start_server(store, history, token=None, port=0):
    handler = _make_handler(store, history, token)
    server = HTTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


class TestSessionStore(unittest.TestCase):
    def test_register_and_list(self):
        with TemporaryDirectory() as d:
            store = SessionStore(Path(d) / "sessions.json")
            store.register("Work", "v100")
            sessions = store.list()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["name"], "Work")
            self.assertEqual(sessions[0]["host"], "v100")

    def test_list_filter_host(self):
        with TemporaryDirectory() as d:
            store = SessionStore(Path(d) / "sessions.json")
            store.register("A", "v100")
            store.register("B", "t14")
            self.assertEqual(len(store.list(host="v100")), 1)
            self.assertEqual(len(store.list(host="t14")), 1)

    def test_remove(self):
        with TemporaryDirectory() as d:
            store = SessionStore(Path(d) / "sessions.json")
            store.register("Work", "v100")
            self.assertTrue(store.remove("Work"))
            self.assertFalse(store.remove("Work"))
            self.assertEqual(len(store.list()), 0)

    def test_persistence(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "sessions.json"
            store = SessionStore(p)
            store.register("Work", "v100")
            store2 = SessionStore(p)
            self.assertEqual(len(store2.list()), 1)

    def test_set_host_reachable(self):
        with TemporaryDirectory() as d:
            store = SessionStore(Path(d) / "sessions.json")
            store.register("Work", "v100")
            self.assertTrue(store.set_host_reachable("Work", True))
            info = store.get("Work")
            self.assertTrue(info["host_reachable"])
            self.assertIsNotNone(info["health_checked_at"])

    def test_same_name_across_hosts(self):
        with TemporaryDirectory() as d:
            store = SessionStore(Path(d) / "sessions.json")
            store.register("Work", "v100")
            store.register("Work", "t14")
            self.assertEqual(len(store.list()), 2)
            self.assertIsNotNone(store.get("Work", host="v100"))
            self.assertIsNotNone(store.get("Work", host="t14"))
            self.assertIsNone(store.get("Work"))


class TestHealthChecker(unittest.TestCase):
    def test_run_once_updates_host_reachability(self):
        with TemporaryDirectory() as d:
            store = SessionStore(Path(d) / "sessions.json")
            store.register("A", "up-host")
            store.register("B", "down-host")

            def _fake_probe(host: str, timeout: float) -> bool:
                return host == "up-host"

            checker = HealthChecker(store, interval=999, timeout=0.1, probe_fn=_fake_probe)
            checker.run_once()

            self.assertTrue(store.get("A")["host_reachable"])
            self.assertFalse(store.get("B")["host_reachable"])


class TestServerAndRegistry(unittest.TestCase):
    def setUp(self):
        self._tmpdir = TemporaryDirectory()
        self.store = SessionStore(Path(self._tmpdir.name) / "sessions.json")
        self.history = HistoryStore(Path(self._tmpdir.name) / "history.json")
        self.server = _start_server(self.store, self.history)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self._tmpdir.cleanup()

    def test_register_and_ls(self):
        result = registry_register(self.url, "Work", "v100")
        self.assertEqual(result["name"], "Work")
        sessions = registry_ls(self.url)
        self.assertEqual(len(sessions), 1)

    def test_get(self):
        registry_register(self.url, "Work", "v100")
        info = registry_get(self.url, "Work")
        self.assertEqual(info["host"], "v100")

    def test_remove(self):
        registry_register(self.url, "Work", "v100")
        registry_remove(self.url, "Work")
        sessions = registry_ls(self.url)
        self.assertEqual(len(sessions), 0)

    def test_get_not_found(self):
        with self.assertRaises(RegistryError) as ctx:
            registry_get(self.url, "nonexistent")
        self.assertEqual(getattr(ctx.exception, "code", None), 404)

    def test_ls_filter(self):
        registry_register(self.url, "A", "v100")
        registry_register(self.url, "B", "t14")
        sessions = registry_ls(self.url, host="v100")
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["name"], "A")

    def test_get_remove_name_with_control_chars(self):
        bad_name = "\x1b[32;1mNT\x1b[m"
        registry_register(self.url, bad_name, "v100")
        info = registry_get(self.url, bad_name)
        self.assertEqual(info["name"], bad_name)
        registry_remove(self.url, bad_name)
        with self.assertRaises(RegistryError):
            registry_get(self.url, bad_name)

    def test_duplicate_name_across_hosts_requires_host_for_get(self):
        registry_register(self.url, "Work", "v100")
        registry_register(self.url, "Work", "t14")
        with self.assertRaises(RegistryError) as ctx:
            registry_get(self.url, "Work")
        self.assertEqual(getattr(ctx.exception, "code", None), 409)
        info = registry_get(self.url, "Work", host="v100")
        self.assertEqual(info["host"], "v100")

    def test_duplicate_name_across_hosts_requires_host_for_remove(self):
        registry_register(self.url, "Work", "v100")
        registry_register(self.url, "Work", "t14")
        with self.assertRaises(RegistryError) as ctx:
            registry_remove(self.url, "Work")
        self.assertEqual(getattr(ctx.exception, "code", None), 409)
        registry_remove(self.url, "Work", host="v100")
        left = registry_ls(self.url)
        self.assertEqual(len(left), 1)
        self.assertEqual(left[0]["host"], "t14")


class TestServerAuth(unittest.TestCase):
    def setUp(self):
        self._tmpdir = TemporaryDirectory()
        self.store = SessionStore(Path(self._tmpdir.name) / "sessions.json")
        self.history = HistoryStore(Path(self._tmpdir.name) / "history.json")
        self.server = _start_server(self.store, self.history, token="secret")
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self._tmpdir.cleanup()

    def test_no_token_rejected(self):
        with self.assertRaises(RegistryError) as ctx:
            registry_ls(self.url)
        self.assertIn("401", str(ctx.exception))
        self.assertEqual(getattr(ctx.exception, "code", None), 401)

    def test_valid_token(self):
        sessions = registry_ls(self.url, token="secret")
        self.assertEqual(sessions, [])

    def test_wrong_token_rejected(self):
        with self.assertRaises(RegistryError) as ctx:
            registry_ls(self.url, token="wrong")
        self.assertEqual(getattr(ctx.exception, "code", None), 401)


class TestHistory(unittest.TestCase):
    def setUp(self):
        self._tmpdir = TemporaryDirectory()
        self.store = SessionStore(Path(self._tmpdir.name) / "sessions.json")
        self.history = HistoryStore(Path(self._tmpdir.name) / "history.json", max_len=10)
        self.server = _start_server(self.store, self.history)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self._tmpdir.cleanup()

    def test_history_append_and_list(self):
        registry_history_add(self.url, "ls")
        registry_history_add(self.url, "open -c v100 -n NT")
        lines = registry_history_list(self.url)
        self.assertEqual(lines[-1], "open -c v100 -n NT")

    def test_history_limit(self):
        for i in range(5):
            registry_history_add(self.url, f"cmd {i}")
        lines = registry_history_list(self.url, limit=2)
        self.assertEqual(lines, ["cmd 3", "cmd 4"])
