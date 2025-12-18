#!/usr/bin/env python3
# mypy: disable-error-code="attr-defined"
"""
RedAudit - Wizard UI Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.6: Extracted from auditor.py for better code organization.
Contains interactive UI methods: prompts, menus, input utilities.
"""

import os
import sys
import ipaddress
from typing import Dict, List

from redaudit.utils.constants import (
    VERSION,
    MAX_CIDR_LENGTH,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    UDP_SCAN_MODE_QUICK,
    UDP_TOP_PORTS,
)
from redaudit.utils.paths import expand_user_path, get_default_reports_base_dir
from redaudit.utils.dry_run import is_dry_run


class WizardMixin:
    """
    Mixin class containing interactive UI methods for RedAudit.

    Provides: input prompts, menus, banners, configuration wizards.
    Expects the inheriting class to have: lang, config, COLORS, t(), print_status().
    """

    # ---------- Screen utilities ----------

    def clear_screen(self) -> None:
        """Clear the terminal screen."""
        if is_dry_run(self.config.get("dry_run")):
            return
        os.system("clear" if os.name == "posix" else "cls")

    def print_banner(self) -> None:
        """Print the RedAudit banner."""
        subtitle = self.t("banner_subtitle")
        banner = f"""
{self.COLORS['FAIL']}
 ____          _    {self.COLORS['BOLD']}{self.COLORS['HEADER']}_             _ _ _{self.COLORS['ENDC']}{self.COLORS['FAIL']}
|  _ \\ ___  __| |  {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ \\  _   _  __| (_) |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
| |_) / _ \\/ _` | {self.COLORS['BOLD']}{self.COLORS['HEADER']}/ _ \\| | | |/ _` | | __|{self.COLORS['ENDC']}{self.COLORS['FAIL']}
|  _ <  __/ (_| |{self.COLORS['BOLD']}{self.COLORS['HEADER']}/ ___ \\ |_| | (_| | | |_{self.COLORS['ENDC']}{self.COLORS['FAIL']}
|_| \\_\\___|\\__,_|{self.COLORS['BOLD']}{self.COLORS['HEADER']}/_/   \\_\\__,_|\\__,_|_|\\__|{self.COLORS['ENDC']}
                                     {self.COLORS['CYAN']}v{VERSION}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
{self.COLORS['BOLD']}{subtitle}{self.COLORS['ENDC']}
{self.COLORS['OKBLUE']}══════════════════════════════════════════════════════{self.COLORS['ENDC']}
"""
        print(banner)

    # ---------- Menu utilities ----------

    def show_main_menu(self) -> int:
        """
        Display main menu and return user choice.

        Returns:
            int: 0=exit, 1=scan, 2=update, 3=diff
        """
        print(f"\n{self.COLORS['HEADER']}RedAudit v{VERSION}{self.COLORS['ENDC']}")
        print("─" * 60)
        print(f"  {self.COLORS['CYAN']}1){self.COLORS['ENDC']} {self.t('menu_option_scan')}")
        print(f"  {self.COLORS['CYAN']}2){self.COLORS['ENDC']} {self.t('menu_option_update')}")
        print(f"  {self.COLORS['CYAN']}3){self.COLORS['ENDC']} {self.t('menu_option_diff')}")
        print(f"  {self.COLORS['CYAN']}0){self.COLORS['ENDC']} {self.t('menu_option_exit')}")
        print("─" * 60)

        while True:
            try:
                ans = input(
                    f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {self.t('menu_prompt')} "
                ).strip()
                if ans in ("0", "1", "2", "3"):
                    return int(ans)
                self.print_status(self.t("menu_invalid_option"), "WARNING")
            except KeyboardInterrupt:
                print("")
                return 0

    def show_legal_warning(self) -> bool:
        """Display legal warning and ask for confirmation."""
        print(f"\n{self.COLORS['WARNING']}{self.t('legal_warning')}{self.COLORS['ENDC']}")
        return self.ask_yes_no(self.t("legal_accept"), default="no")

    # ---------- Input utilities ----------

    def ask_yes_no(self, question: str, default: str = "yes") -> bool:
        """Ask a yes/no question."""
        default = default.lower()
        opts = (
            self.t("ask_yes_no_opts")
            if default in ("yes", "y", "s", "si", "sí")
            else self.t("ask_yes_no_opts_neg")
        )
        valid = {
            "yes": True,
            "y": True,
            "s": True,
            "si": True,
            "sí": True,
            "no": False,
            "n": False,
        }
        while True:
            try:
                print(f"\n{self.COLORS['OKBLUE']}{'—' * 60}{self.COLORS['ENDC']}")
                ans = (
                    input(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}{opts}: ")
                    .strip()
                    .lower()
                )
                if ans == "":
                    return valid.get(default, True)
                if ans in valid:
                    return valid[ans]
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_number(self, question: str, default=10, min_val: int = 1, max_val: int = 1000):
        """Ask for a number within a range."""
        default_return = default
        default_display = default
        if isinstance(default, str) and default.lower() in ("all", "todos", "todo"):
            default_return = "all"
            default_display = "todos" if self.lang == "es" else "all"
        while True:
            try:
                print(f"\n{self.COLORS['OKBLUE']}{'—' * 60}{self.COLORS['ENDC']}")
                ans = input(
                    f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question} [{default_display}]: "
                ).strip()
                if ans == "":
                    return default_return
                if ans.lower() in ("todos", "todo", "all"):
                    return "all"
                try:
                    num = int(ans)
                    if min_val <= num <= max_val:
                        return num
                    self.print_status(self.t("val_out_of_range", min_val, max_val), "WARNING")
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_choice(self, question: str, options: List[str], default: int = 0) -> int:
        """Ask to choose from a list of options."""
        print(f"\n{self.COLORS['OKBLUE']}{'—' * 60}{self.COLORS['ENDC']}")
        print(f"{self.COLORS['CYAN']}?{self.COLORS['ENDC']} {question}")
        for i, opt in enumerate(options):
            marker = f"{self.COLORS['BOLD']}>{self.COLORS['ENDC']}" if i == default else " "
            print(f"  {marker} {i + 1}. {opt}")
        while True:
            try:
                ans = input(
                    f"\n{self.t('select_opt')} [1-{len(options)}] ({default + 1}): "
                ).strip()
                if ans == "":
                    return default
                try:
                    idx = int(ans) - 1
                    if 0 <= idx < len(options):
                        return idx
                except ValueError:
                    continue
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    def ask_manual_network(self) -> str:
        """Ask for manual network CIDR input."""
        while True:
            try:
                net = input(
                    f"\n{self.COLORS['CYAN']}?{self.COLORS['ENDC']} CIDR (e.g. 192.168.1.0/24): "
                ).strip()
                if len(net) > MAX_CIDR_LENGTH:
                    self.print_status(self.t("invalid_cidr"), "WARNING")
                    continue
                try:
                    ipaddress.ip_network(net, strict=False)
                    return net
                except ValueError:
                    self.print_status(self.t("invalid_cidr"), "WARNING")
            except KeyboardInterrupt:
                print("")
                self.signal_handler(None, None)
                sys.exit(0)

    # ---------- Defaults summary ----------

    def _show_defaults_summary(self, persisted_defaults: Dict) -> None:
        """Display summary of persisted defaults."""
        self.print_status(self.t("defaults_summary_title"), "INFO")

        def fmt_targets(val):
            if not isinstance(val, list) or not val:
                return "-"
            cleaned = [t.strip() for t in val if isinstance(t, str) and t.strip()]
            return ", ".join(cleaned) if cleaned else "-"

        def fmt_bool(val):
            if val is None:
                return "-"
            return self.t("enabled") if val else self.t("disabled")

        fields = [
            ("defaults_summary_targets", fmt_targets(persisted_defaults.get("target_networks"))),
            ("defaults_summary_scan_mode", persisted_defaults.get("scan_mode")),
            ("defaults_summary_threads", persisted_defaults.get("threads")),
            ("defaults_summary_output", persisted_defaults.get("output_dir")),
            ("defaults_summary_rate_limit", persisted_defaults.get("rate_limit")),
            ("defaults_summary_udp_mode", persisted_defaults.get("udp_mode")),
            ("defaults_summary_udp_ports", persisted_defaults.get("udp_top_ports")),
            ("defaults_summary_topology", fmt_bool(persisted_defaults.get("topology_enabled"))),
            (
                "defaults_summary_web_vulns",
                fmt_bool(persisted_defaults.get("scan_vulnerabilities")),
            ),
            ("defaults_summary_cve_lookup", fmt_bool(persisted_defaults.get("cve_lookup_enabled"))),
            ("defaults_summary_txt_report", fmt_bool(persisted_defaults.get("generate_txt"))),
            ("defaults_summary_html_report", fmt_bool(persisted_defaults.get("generate_html"))),
        ]

        for key, val in fields:
            display_val = val if val is not None else "-"
            self.print_status(f"- {self.t(key)}: {display_val}", "INFO")

    def _apply_run_defaults(self, defaults_for_run: Dict) -> None:
        """Apply persisted defaults to self.config without prompts."""
        # 1. Scan Mode
        self.config["scan_mode"] = defaults_for_run.get("scan_mode", "normal")

        # 2. Max Hosts
        self.config["max_hosts_value"] = "all"

        # 3. Threads
        threads = defaults_for_run.get("threads")
        if isinstance(threads, int) and MIN_THREADS <= threads <= MAX_THREADS:
            self.config["threads"] = threads
        else:
            self.config["threads"] = DEFAULT_THREADS

        # 4. Rate Limit
        rate_limit = defaults_for_run.get("rate_limit")
        if isinstance(rate_limit, (int, float)) and rate_limit > 0:
            self.rate_limit_delay = float(min(max(rate_limit, 0), 60))
        else:
            self.rate_limit_delay = 0.0

        # 5. Vulnerabilities
        self.config["scan_vulnerabilities"] = defaults_for_run.get("scan_vulnerabilities", True)
        self.config["cve_lookup_enabled"] = defaults_for_run.get("cve_lookup_enabled", False)

        # 6. Output Dir
        out_dir = defaults_for_run.get("output_dir")
        if isinstance(out_dir, str) and out_dir.strip():
            self.config["output_dir"] = expand_user_path(out_dir.strip())
        else:
            self.config["output_dir"] = get_default_reports_base_dir()

        self.config["save_txt_report"] = defaults_for_run.get("generate_txt", True)
        self.config["save_html_report"] = defaults_for_run.get("generate_html", True)

        # 7. UDP Configuration
        self.config["udp_mode"] = defaults_for_run.get("udp_mode", UDP_SCAN_MODE_QUICK)
        self.config["udp_top_ports"] = defaults_for_run.get("udp_top_ports", UDP_TOP_PORTS)

        # 8. Topology
        self.config["topology_enabled"] = defaults_for_run.get("topology_enabled", False)
        self.config["topology_only"] = defaults_for_run.get("topology_only", False)
