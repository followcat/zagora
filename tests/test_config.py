import os
import unittest
from unittest import mock

from zagora.config import CONFIG_ENV_HOST, CONFIG_ENV_TOKEN
from zagora.config import resolve_server, resolve_token


class TestResolveServer(unittest.TestCase):
    def test_cli_wins(self):
        with mock.patch.dict(os.environ, {CONFIG_ENV_HOST: "env"}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={}):
                self.assertEqual(resolve_server("cli"), "cli")

    def test_env_used(self):
        with mock.patch.dict(os.environ, {CONFIG_ENV_HOST: "http://env:9876"}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={}):
                self.assertEqual(resolve_server(None), "http://env:9876")

    def test_config_used(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={"server": "http://C:9876"}):
                self.assertEqual(resolve_server(None), "http://C:9876")

    def test_none_when_nothing(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={}):
                self.assertIsNone(resolve_server(None))


class TestResolveToken(unittest.TestCase):
    def test_cli_wins(self):
        with mock.patch.dict(os.environ, {CONFIG_ENV_TOKEN: "env-tok"}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={}):
                self.assertEqual(resolve_token("cli-tok"), "cli-tok")

    def test_env_used(self):
        with mock.patch.dict(os.environ, {CONFIG_ENV_TOKEN: "env-tok"}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={}):
                self.assertEqual(resolve_token(None), "env-tok")

    def test_config_used(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("zagora.config.load_config", return_value={"token": "cfg-tok"}):
                self.assertEqual(resolve_token(None), "cfg-tok")
