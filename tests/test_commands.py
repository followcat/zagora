import unittest

from zagora.cli import build_parser
from zagora.exec import ssh_via_tailscale, tailscale_ssh


class TestCommands(unittest.TestCase):
    def test_tailscale_ssh_argv(self):
        argv = tailscale_ssh("C", ["zellij", "list-sessions"])
        self.assertEqual(argv[:4], ["tailscale", "ssh", "C", "--"])
        self.assertEqual(argv[4:], ["zellij", "list-sessions"])

    def test_ssh_via_tailscale_argv(self):
        argv = ssh_via_tailscale("C", ["zellij", "list-sessions"])
        self.assertEqual(argv[0], "ssh")
        self.assertIn("ProxyCommand=tailscale nc %h %p", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)


class TestParser(unittest.TestCase):
    def test_serve(self):
        p = build_parser()
        args = p.parse_args(["serve", "--port", "1234"])
        self.assertEqual(args.cmd, "serve")
        self.assertEqual(args.port, 1234)

    def test_completion_parses(self):
        p = build_parser()
        args = p.parse_args(["completion", "--shell", "bash"])
        self.assertEqual(args.cmd, "completion")
        self.assertEqual(args.shell, "bash")

    def test_open(self):
        p = build_parser()
        args = p.parse_args(["open", "-c", "v100", "--name", "Work"])
        self.assertEqual(args.cmd, "open")
        self.assertEqual(args.connect, "v100")
        self.assertEqual(args.name, "Work")

    def test_attach(self):
        p = build_parser()
        args = p.parse_args(["attach", "--name", "Work"])
        self.assertEqual(args.cmd, "attach")
        self.assertEqual(args.name, "Work")

    def test_attach_alias_and_short_name(self):
        p = build_parser()
        args = p.parse_args(["a", "-n", "Work"])
        self.assertEqual(args.cmd, "a")
        self.assertEqual(args.name, "Work")

    def test_ls(self):
        p = build_parser()
        args = p.parse_args(["ls"])
        self.assertEqual(args.cmd, "ls")

    def test_no_subcommand_enters_interactive(self):
        p = build_parser()
        args = p.parse_args(["--host", "http://C:9876"])
        self.assertIsNone(getattr(args, "cmd", None))

    def test_ls_with_filter(self):
        p = build_parser()
        args = p.parse_args(["ls", "-c", "v100"])
        self.assertEqual(args.connect, "v100")

    def test_kill(self):
        p = build_parser()
        args = p.parse_args(["kill", "--name", "Work"])
        self.assertEqual(args.cmd, "kill")

    def test_refresh_parses(self):
        p = build_parser()
        args = p.parse_args(["refresh"])
        self.assertEqual(args.cmd, "refresh")

    def test_update_parses(self):
        p = build_parser()
        args = p.parse_args(["update"])
        self.assertEqual(args.cmd, "update")

    def test_global_host_before_subcommand(self):
        p = build_parser()
        args = p.parse_args(["--host", "http://C:9876", "ls"])
        self.assertEqual(args.host, "http://C:9876")

    def test_install_zellij(self):
        p = build_parser()
        args = p.parse_args(["install-zellij", "-c", "v100"])
        self.assertEqual(args.cmd, "install-zellij")
        self.assertEqual(args.connect, "v100")
