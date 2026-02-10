import json
import threading
import time
import unittest
from http.server import HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from zagora.registry import RegistryError, registry_get, registry_ls, registry_register, registry_remove
from zagora.server import SessionStore, _make_handler


def _start_server(store, token=None, port=0):
    handler = _make_handler(store, token)
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


class TestServerAndRegistry(unittest.TestCase):
    def setUp(self):
        self._tmpdir = TemporaryDirectory()
        self.store = SessionStore(Path(self._tmpdir.name) / "sessions.json")
        self.server = _start_server(self.store)
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


class TestServerAuth(unittest.TestCase):
    def setUp(self):
        self._tmpdir = TemporaryDirectory()
        self.store = SessionStore(Path(self._tmpdir.name) / "sessions.json")
        self.server = _start_server(self.store, token="secret")
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
