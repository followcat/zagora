import argparse
import io
import subprocess
import unittest
from unittest.mock import patch

import zagora.cli as cli
from zagora.cli import build_parser
from zagora.exec import ssh_via_tailscale, tailscale_ssh


class TestCommands(unittest.TestCase):
    def test_tailscale_ssh_argv(self):
        argv = tailscale_ssh("C", ["zellij", "list-sessions"])
        self.assertEqual(argv[:4], ["tailscale", "ssh", "C", "--"])
        self.assertEqual(argv[4:], ["zellij", "list-sessions"])

    def test_tailscale_ssh_argv_with_x11(self):
        argv = tailscale_ssh("C", ["zellij", "list-sessions"], x11=True)
        self.assertEqual(argv[:5], ["tailscale", "ssh", "-Y", "C", "--"])
        self.assertEqual(argv[5:], ["zellij", "list-sessions"])

    def test_ssh_via_tailscale_argv(self):
        argv = ssh_via_tailscale("C", ["zellij", "list-sessions"])
        self.assertEqual(argv[0], "ssh")
        self.assertNotIn("-Y", argv)
        self.assertIn("ProxyCommand=tailscale nc %h %p", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)
        self.assertIn("ControlMaster=auto", argv)
        self.assertIn("ControlPersist=120", argv)
        self.assertIn("ControlPath=~/.ssh/zagora-%C", argv)

    def test_ssh_via_tailscale_argv_with_x11(self):
        argv = ssh_via_tailscale("C", ["zellij", "list-sessions"], x11=True)
        self.assertEqual(argv[0], "ssh")
        self.assertIn("-Y", argv)
        self.assertIn("ProxyCommand=tailscale nc %h %p", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)
        self.assertIn("ControlMaster=auto", argv)
        self.assertIn("ControlPersist=120", argv)
        self.assertIn("ControlPath=~/.ssh/zagora-%C", argv)

    def test_ssh_via_tailscale_argv_without_connection_cache(self):
        argv = ssh_via_tailscale("C", ["zellij", "list-sessions"], control_persist="off")
        self.assertEqual(argv[0], "ssh")
        self.assertNotIn("ControlMaster=auto", argv)
        self.assertNotIn("ControlPersist=120", argv)
        self.assertNotIn("ControlPath=~/.ssh/zagora-%C", argv)

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

    def test_short_ts(self):
        self.assertEqual(cli._short_ts("2026-02-12T08:08:08+00:00"), "2026-02-12 08:08:08")
        self.assertEqual(cli._short_ts(""), "-")
        self.assertEqual(cli._short_ts(None), "-")

    def test_cmd_ls_shows_extended_status(self):
        args = argparse.Namespace(host="http://s:9876", token=None, connect=None)
        sessions = [
            {
                "name": "NTcli",
                "host": "v100",
                "status": "running",
                "host_reachable": True,
                "last_seen": "2026-02-12T08:08:08+00:00",
                "health_checked_at": "2026-02-12T08:09:09+00:00",
                "created_at": "2026-02-12T08:00:00+00:00",
            }
        ]
        with (
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli.registry_ls", return_value=sessions),
            patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cli.cmd_ls(args)
            self.assertEqual(rc, 0)
            text = out.getvalue()
            self.assertIn("host:up", text)
            self.assertIn("seen:2026-02-12 08:08:08", text)
            self.assertIn("health:2026-02-12 08:09:09", text)

    def test_cmd_ls_merges_legacy_ansi_names(self):
        args = argparse.Namespace(host="http://s:9876", token=None, connect=None)
        sessions = [
            {"name": "\x1b[32;1mNT\x1b[m", "host": "v100", "status": "running", "last_seen": "2026-02-12T08:00:00+00:00"},
            {"name": "NT", "host": "v100", "status": "running", "last_seen": "2026-02-12T08:10:00+00:00"},
        ]
        with (
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli.registry_ls", return_value=sessions),
            patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cli.cmd_ls(args)
            self.assertEqual(rc, 0)
            lines = [ln for ln in out.getvalue().splitlines() if "\t" in ln]
            self.assertEqual(len(lines), 1)
            self.assertIn("NT\tv100\trunning", lines[0])

    def test_cmd_ls_keeps_same_name_on_different_hosts(self):
        args = argparse.Namespace(host="http://s:9876", token=None, connect=None)
        sessions = [
            {"name": "NT", "host": "v100", "status": "running", "last_seen": "2026-02-12T08:10:00+00:00"},
            {"name": "NT", "host": "t14", "status": "running", "last_seen": "2026-02-12T08:11:00+00:00"},
        ]
        with (
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli.registry_ls", return_value=sessions),
            patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cli.cmd_ls(args)
            self.assertEqual(rc, 0)
            lines = [ln for ln in out.getvalue().splitlines() if "\t" in ln]
            self.assertEqual(len(lines), 2)

    def test_repl_shorthand_open(self):
        out = cli._rewrite_repl_shorthand(["open", "v100", "NT"])
        self.assertEqual(out, ["open", "-c", "v100", "-n", "NT"])

    def test_repl_shorthand_attach_and_kill(self):
        self.assertEqual(cli._rewrite_repl_shorthand(["a", "NT"]), ["a", "-n", "NT"])
        self.assertEqual(cli._rewrite_repl_shorthand(["kill", "v100", "NT"]), ["kill", "-c", "v100", "-n", "NT"])
        self.assertEqual(cli._rewrite_repl_shorthand(["attach", "v100", "NT"]), ["attach", "-c", "v100", "-n", "NT"])

    def test_repl_shorthand_host_filters(self):
        self.assertEqual(cli._rewrite_repl_shorthand(["ls", "v100"]), ["ls", "-c", "v100"])
        self.assertEqual(
            cli._rewrite_repl_shorthand(["refresh", "v100"]),
            ["refresh", "-c", "v100"],
        )
        self.assertEqual(
            cli._rewrite_repl_shorthand(["sync", "v100"]),
            ["sync", "-c", "v100"],
        )

    def test_parse_zellij_ls_names(self):
        text = "NT [Created 1h ago]\nWork [Created now]\n"
        self.assertEqual(cli._parse_zellij_ls_names(text), ["NT", "Work"])
        self.assertEqual(cli._parse_zellij_ls_names("No active zellij sessions found.\n"), [])
        self.assertEqual(
            cli._parse_zellij_ls_names("followcat@100.120.110.114's password:\nNTcli [Created now]\n"),
            ["NTcli"],
        )
        self.assertEqual(
            cli._parse_zellij_ls_names("\x1b[32;1mNTcli\x1b[m [Created now]\n"),
            ["NTcli"],
        )

    def test_cmd_open_blocks_legacy_ansi_duplicate(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto", name="NT")
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli.registry_ls", return_value=[{"name": "\x1b[32;1mNT\x1b[m", "host": "v100"}]),
            patch("zagora.cli.registry_register") as reg_mock,
        ):
            with self.assertRaises(cli.ZagoraError):
                cli.cmd_open(args)
            reg_mock.assert_not_called()

    def test_cmd_open_allows_same_name_on_other_host(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto", name="NT")
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli.registry_ls", return_value=[{"name": "NT", "host": "t14"}]),
            patch("zagora.cli.registry_register"),
            patch("zagora.cli._exec_remote_interactive", return_value=0),
            patch("zagora.cli._reconcile_session_after_interactive"),
        ):
            rc = cli.cmd_open(args)
            self.assertEqual(rc, 0)

    def test_lookup_session_host_falls_back_to_legacy_normalized_name(self):
        with (
            patch("zagora.cli.registry_ls", return_value=[{"name": "\x1b[32;1mNT\x1b[m", "host": "v100"}]),
        ):
            host = cli._lookup_session_host("http://s:9876", None, "NT")
            self.assertEqual(host, "v100")

    def test_lookup_session_target_supports_case_insensitive_and_prefix(self):
        with (
            patch("zagora.cli.registry_ls", return_value=[{"name": "GpuCheck", "host": "v100"}]),
        ):
            host, resolved = cli._lookup_session_target("http://s:9876", None, "gpu")
            self.assertEqual(host, "v100")
            self.assertEqual(resolved, "GpuCheck")

    def test_resolve_name_arg_accepts_positional(self):
        args = argparse.Namespace(name=None, name_pos="gpucheck")
        self.assertEqual(cli._resolve_name_arg(args), "gpucheck")

    def test_auth_or_transport_issue_detector(self):
        self.assertTrue(cli._looks_like_auth_or_transport_issue("followcat@x password:"))
        self.assertTrue(cli._looks_like_auth_or_transport_issue("Permission denied"))
        self.assertFalse(cli._looks_like_auth_or_transport_issue("NTcli [Created now]"))

    def test_cmd_sync_registers_remote_and_removes_stale(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto")
        remote = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="A\nB\n", stderr="")
        current = [{"name": "A", "host": "v100"}, {"name": "OLD", "host": "v100"}]
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch("zagora.cli.registry_ls", return_value=current),
            patch("zagora.cli.registry_register") as reg_mock,
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_sync(args)
            self.assertEqual(rc, 0)
            reg_names = [c.args[1] for c in reg_mock.call_args_list]
            self.assertEqual(reg_names, ["A", "B"])
            rm_mock.assert_called_once_with("http://s:9876", "OLD", token=None, host="v100")

    def test_cmd_sync_skips_destructive_when_password_prompt_and_empty(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto")
        remote = subprocess.CompletedProcess(
            args=["ssh"], returncode=0, stdout="", stderr="followcat@100.120.110.114's password:"
        )
        current = [{"name": "A", "host": "v100"}]
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch("zagora.cli.registry_ls", return_value=current),
            patch("zagora.cli.registry_register") as reg_mock,
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_sync(args)
            self.assertEqual(rc, 1)
            reg_mock.assert_not_called()
            rm_mock.assert_not_called()

    def test_cmd_sync_ignore_404_when_removing_stale(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto")
        remote = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="A\n", stderr="")
        current = [{"name": "A", "host": "v100"}, {"name": "OLD", "host": "v100"}]
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch("zagora.cli.registry_ls", return_value=current),
            patch("zagora.cli.registry_register"),
            patch("zagora.cli.registry_remove", side_effect=cli.RegistryError("not found", code=404)),
        ):
            rc = cli.cmd_sync(args)
            self.assertEqual(rc, 0)

    def test_cmd_sync_removes_all_legacy_name_variants(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto")
        remote = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="No active zellij sessions found.\n", stderr="")
        current = [{"name": "NT", "host": "v100"}, {"name": "\x1b[32;1mNT\x1b[m", "host": "v100"}]
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch("zagora.cli.registry_ls", return_value=current),
            patch("zagora.cli.registry_register"),
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_sync(args)
            self.assertEqual(rc, 0)
            removed_names = [c.args[1] for c in rm_mock.call_args_list]
            self.assertCountEqual(removed_names, ["NT", "\x1b[32;1mNT\x1b[m"])
            self.assertTrue(all(c.kwargs.get("host") == "v100" for c in rm_mock.call_args_list))

    def test_cmd_sync_cleans_legacy_alias_when_session_running(self):
        args = argparse.Namespace(connect="v100", host="http://s:9876", token=None, transport="auto")
        remote = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="NT\n", stderr="")
        current = [{"name": "NT", "host": "v100"}, {"name": "\x1b[32;1mNT\x1b[m", "host": "v100"}]
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch("zagora.cli.registry_ls", return_value=current),
            patch("zagora.cli.registry_register"),
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_sync(args)
            self.assertEqual(rc, 0)
            removed_names = [c.args[1] for c in rm_mock.call_args_list]
            self.assertEqual(removed_names, ["\x1b[32;1mNT\x1b[m"])
            self.assertTrue(all(c.kwargs.get("host") == "v100" for c in rm_mock.call_args_list))

    def test_cmd_refresh_does_not_prune_on_password_prompt(self):
        args = argparse.Namespace(host="http://s:9876", token=None, transport="auto", connect=None)
        remote = subprocess.CompletedProcess(
            args=["ssh"], returncode=255, stdout="", stderr="followcat@100.120.110.114's password:"
        )
        sessions = [{"name": "NTcli", "host": "v100", "status": "running"}]
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli.registry_ls", return_value=sessions),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch("zagora.cli.registry_remove") as rm_mock,
            patch("zagora.cli.registry_register") as reg_mock,
        ):
            rc = cli.cmd_refresh(args)
            self.assertEqual(rc, 0)
            rm_mock.assert_not_called()
            reg_mock.assert_called_once_with("http://s:9876", "NTcli", "v100", token=None, status="unreachable")

    def test_cmd_kill_removes_legacy_variants(self):
        args = argparse.Namespace(
            host="http://s:9876",
            token=None,
            transport="auto",
            connect="v100",
            name="NT",
        )
        remote = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="", stderr="")
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._run_remote_capture", return_value=remote),
            patch(
                "zagora.cli.registry_ls",
                return_value=[{"name": "NT", "host": "v100"}, {"name": "\x1b[32;1mNT\x1b[m", "host": "v100"}],
            ),
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_kill(args)
            self.assertEqual(rc, 0)
            removed_names = [c.args[1] for c in rm_mock.call_args_list]
            self.assertCountEqual(removed_names, ["NT", "\x1b[32;1mNT\x1b[m"])
            self.assertTrue(all(c.kwargs.get("host") == "v100" for c in rm_mock.call_args_list))

    def test_cmd_attach_reconcile_removes_when_session_quit(self):
        args = argparse.Namespace(
            host="http://s:9876",
            token=None,
            transport="auto",
            connect="v100",
            name="NT",
            _repl_mode=True,
        )
        remote_ls = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="NTcli\n", stderr="")
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._exec_remote_interactive", return_value=0),
            patch("zagora.cli._run_remote_capture", return_value=remote_ls),
            patch(
                "zagora.cli.registry_ls",
                return_value=[{"name": "NT", "host": "v100"}, {"name": "\x1b[32;1mNT\x1b[m", "host": "v100"}],
            ),
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_attach(args)
            self.assertEqual(rc, 0)
            removed_names = [c.args[1] for c in rm_mock.call_args_list]
            self.assertCountEqual(removed_names, ["NT", "\x1b[32;1mNT\x1b[m"])
            self.assertTrue(all(c.kwargs.get("host") == "v100" for c in rm_mock.call_args_list))

    def test_cmd_attach_reconcile_keeps_when_still_running(self):
        args = argparse.Namespace(
            host="http://s:9876",
            token=None,
            transport="auto",
            connect="v100",
            name="NT",
            _repl_mode=True,
        )
        remote_ls = subprocess.CompletedProcess(args=["ssh"], returncode=0, stdout="NT [Created now]\n", stderr="")
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._exec_remote_interactive", return_value=0),
            patch("zagora.cli._run_remote_capture", return_value=remote_ls),
            patch("zagora.cli.registry_register") as reg_mock,
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_attach(args)
            self.assertEqual(rc, 0)
            reg_mock.assert_called_once_with("http://s:9876", "NT", "v100", token=None, status="running")
            rm_mock.assert_not_called()

    def test_cmd_attach_reconcile_removes_with_password_prompt_when_output_definitive(self):
        args = argparse.Namespace(
            host="http://s:9876",
            token=None,
            transport="auto",
            connect="v100",
            name="NT",
            _repl_mode=True,
        )
        remote_ls = subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout="No active zellij sessions found.\n",
            stderr="followcat@100.120.110.114's password:",
        )
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._exec_remote_interactive", return_value=0),
            patch("zagora.cli._run_remote_capture", return_value=remote_ls),
            patch("zagora.cli.registry_ls", return_value=[{"name": "NT", "host": "v100"}]),
            patch("zagora.cli.registry_remove") as rm_mock,
        ):
            rc = cli.cmd_attach(args)
            self.assertEqual(rc, 0)
            rm_mock.assert_called_once_with("http://s:9876", "NT", token=None, host="v100")

    def test_cmd_attach_uses_positional_name(self):
        args = argparse.Namespace(
            host="http://s:9876",
            token=None,
            transport="auto",
            connect=None,
            name=None,
            name_pos="gpucheck",
            _repl_mode=False,
        )
        with (
            patch("zagora.cli.require_cmd"),
            patch("zagora.cli._server_or_exit", return_value="http://s:9876"),
            patch("zagora.cli._token", return_value=None),
            patch("zagora.cli._lookup_session_target", return_value=("v100", "GpuCheck")) as lookup_mock,
            patch("zagora.cli._exec_remote_interactive", return_value=0) as exec_mock,
        ):
            rc = cli.cmd_attach(args)
            self.assertEqual(rc, 0)
            lookup_mock.assert_called_once_with("http://s:9876", None, "gpucheck")
            self.assertEqual(exec_mock.call_args.args[1], "v100")


class TestParser(unittest.TestCase):
    def test_serve(self):
        p = build_parser()
        args = p.parse_args(["serve", "--port", "1234"])
        self.assertEqual(args.cmd, "serve")
        self.assertEqual(args.port, 1234)

    def test_serve_health_opts(self):
        p = build_parser()
        args = p.parse_args(["serve", "--health-interval", "10", "--health-timeout", "1.5"])
        self.assertEqual(args.health_interval, 10.0)
        self.assertEqual(args.health_timeout, 1.5)

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

    def test_attach_alias_positional_name(self):
        p = build_parser()
        args = p.parse_args(["a", "Work"])
        self.assertEqual(args.cmd, "a")
        self.assertEqual(args.name_pos, "Work")

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

    def test_sync_parses(self):
        p = build_parser()
        args = p.parse_args(["sync", "-c", "v100"])
        self.assertEqual(args.cmd, "sync")
        self.assertEqual(args.connect, "v100")

    def test_global_host_before_subcommand(self):
        p = build_parser()
        args = p.parse_args(["--host", "http://C:9876", "ls"])
        self.assertEqual(args.host, "http://C:9876")

    def test_global_ssh_control_persist_before_subcommand(self):
        p = build_parser()
        args = p.parse_args(["--ssh-control-persist", "10m", "ls"])
        self.assertEqual(args.ssh_control_persist, "10m")

    def test_install_zellij(self):
        p = build_parser()
        args = p.parse_args(["install-zellij", "-c", "v100"])
        self.assertEqual(args.cmd, "install-zellij")
        self.assertEqual(args.connect, "v100")

    def test_install_zellij_with_ssh_control_persist(self):
        p = build_parser()
        args = p.parse_args(["install-zellij", "-c", "v100", "--ssh-control-persist", "15m"])
        self.assertEqual(args.ssh_control_persist, "15m")
