import argparse
import subprocess
import unittest
from unittest.mock import patch

import zagora.cli as cli
from zagora.cli import build_parser
from zagora.exec import ssh_via_tailscale, tailscale_ssh


class TestCommands(unittest.TestCase):
    def test_tailscale_ssh_argv(self):
        argv = tailscale_ssh("C", ["zellij", "list-sessions"])
        self.assertEqual(argv[:5], ["tailscale", "ssh", "-Y", "C", "--"])
        self.assertEqual(argv[5:], ["zellij", "list-sessions"])

    def test_ssh_via_tailscale_argv(self):
        argv = ssh_via_tailscale("C", ["zellij", "list-sessions"])
        self.assertEqual(argv[0], "ssh")
        self.assertIn("-Y", argv)
        self.assertIn("ProxyCommand=tailscale nc %h %p", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)

    def test_exec_remote_interactive_uses_subprocess_in_repl(self):
        args = argparse.Namespace(transport="auto", _repl_mode=True)
        runs = [
            subprocess.CompletedProcess(args=["tailscale", "ssh"], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=["tailscale", "ssh"], returncode=0, stdout="", stderr=""),
        ]
        with patch("subprocess.run", side_effect=runs) as run_mock, patch("zagora.cli.exec_interactive") as exec_mock:
            rc = cli._exec_remote_interactive(args, "C", ["zellij", "attach", "Work"])
            self.assertEqual(rc, 0)
            self.assertEqual(run_mock.call_count, 2)
            self.assertIn("preexec_fn", run_mock.call_args_list[1].kwargs)
            exec_mock.assert_not_called()

    def test_exec_remote_interactive_execs_outside_repl(self):
        args = argparse.Namespace(transport="ssh")
        with patch("zagora.cli.exec_interactive") as exec_mock:
            rc = cli._exec_remote_interactive(args, "C", ["zellij", "attach", "Work"])
            self.assertEqual(rc, 0)
            self.assertTrue(exec_mock.called)

    def test_run_remote_capture_falls_back_when_tailscale_rejects_y(self):
        args = argparse.Namespace(transport="auto")
        runs = [
            subprocess.CompletedProcess(
                args=["tailscale", "ssh"], returncode=2, stdout="", stderr="flag provided but not defined: -Y"
            ),
            subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="ok\n", stderr=""),
        ]
        with patch("zagora.cli.run_capture", side_effect=runs) as run_mock:
            out = cli._run_remote_capture(args, "C", ["true"])
            self.assertEqual(out.returncode, 0)
            self.assertEqual(run_mock.call_args_list[1].args[0][0], "ssh")

    def test_exec_remote_interactive_falls_back_when_tailscale_rejects_y(self):
        args = argparse.Namespace(transport="tailscale")
        pre = subprocess.CompletedProcess(
            args=["tailscale", "ssh"], returncode=2, stdout="", stderr="flag provided but not defined: -Y"
        )
        with patch("subprocess.run", return_value=pre), patch("zagora.cli.exec_interactive") as exec_mock:
            rc = cli._exec_remote_interactive(args, "C", ["zellij", "attach", "Work"])
            self.assertEqual(rc, 0)
            self.assertEqual(exec_mock.call_args.args[0][0], "ssh")

    def test_normalize_server_url_defaults(self):
        self.assertEqual(cli._normalize_server_url("t14"), "http://t14:9876")
        self.assertEqual(cli._normalize_server_url("t14:9999"), "http://t14:9999")
        self.assertEqual(cli._normalize_server_url("http://t14:9999/"), "http://t14:9999")

    def test_repl_shorthand_open(self):
        out = cli._rewrite_repl_shorthand(["open", "v100", "NT"])
        self.assertEqual(out, ["open", "-c", "v100", "-n", "NT"])

    def test_repl_shorthand_attach_and_kill(self):
        self.assertEqual(cli._rewrite_repl_shorthand(["a", "NT"]), ["a", "-n", "NT"])
        self.assertEqual(cli._rewrite_repl_shorthand(["kill", "NT", "v100"]), ["kill", "-n", "NT", "-c", "v100"])

    def test_repl_shorthand_host_filters(self):
        self.assertEqual(cli._rewrite_repl_shorthand(["ls", "v100"]), ["ls", "-c", "v100"])
        self.assertEqual(
            cli._rewrite_repl_shorthand(["refresh", "v100"]),
            ["refresh", "-c", "v100"],
        )


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

    def test_refresh_no_prune_flags_parse(self):
        p = build_parser()
        args = p.parse_args(["refresh", "--no-prune", "--no-prune-unreachable"])
        self.assertTrue(args.no_prune)
        self.assertTrue(args.no_prune_unreachable)

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
