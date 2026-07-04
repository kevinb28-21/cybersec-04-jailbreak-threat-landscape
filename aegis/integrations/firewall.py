"""Optional iptables integration for real perimeter blocking."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from aegis.config import settings

logger = logging.getLogger(__name__)

CHAIN_NAME = "AEGIS-BLOCK"
_input_jump_installed = False


@dataclass
class FirewallState:
    blocked_ips: set[str] = field(default_factory=set)
    isolated_hosts: set[str] = field(default_factory=set)
    rules: dict[str, str] = field(default_factory=dict)


_state = FirewallState()


def is_iptables_available() -> bool:
    return shutil.which("iptables") is not None and not settings.soar_simulation_mode


def _ensure_chain() -> None:
    global _input_jump_installed
    if settings.soar_simulation_mode or not shutil.which("iptables"):
        return
    subprocess.run(["iptables", "-N", CHAIN_NAME], capture_output=True, check=False)
    if not _input_jump_installed:
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-j", CHAIN_NAME],
            capture_output=True, check=False,
        )
        if check.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "-j", CHAIN_NAME], capture_output=True, check=False)
        _input_jump_installed = True


def block_ip(ip: str) -> tuple[bool, str, str]:
    """Block IP via iptables. Returns (success, message, rule_id)."""
    rule_id = f"block-{ip.replace('.', '-')}"
    prefix = "[SIMULATED] " if settings.soar_simulation_mode else ""

    if settings.soar_simulation_mode:
        _state.blocked_ips.add(ip)
        _state.rules[rule_id] = ip
        return True, f"{prefix}blocked IP {ip}", rule_id

    if not is_iptables_available():
        _state.blocked_ips.add(ip)
        _state.rules[rule_id] = ip
        return True, f"[LOCAL-TRACKED] blocked IP {ip} (iptables unavailable)", rule_id

    try:
        _ensure_chain()
        subprocess.run(
            ["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, check=True,
        )
        _state.blocked_ips.add(ip)
        _state.rules[rule_id] = ip
        logger.warning("iptables: blocked %s", ip)
        return True, f"blocked IP {ip} via iptables", rule_id
    except subprocess.CalledProcessError as exc:
        return False, f"iptables failed: {exc.stderr}", rule_id


def isolate_host(host_id: str) -> tuple[bool, str, str]:
    """Track host isolation (production: integrate with EDR/NAC)."""
    rule_id = f"isolate-{host_id.replace('.', '-')}"
    prefix = "[SIMULATED] " if settings.soar_simulation_mode else ""
    _state.isolated_hosts.add(host_id)
    _state.rules[rule_id] = host_id
    return True, f"{prefix}isolated host {host_id}", rule_id


def rollback_block(rule_id: str) -> tuple[bool, str]:
    ip_or_host = _state.rules.get(rule_id)
    if not ip_or_host:
        return True, f"no rule to rollback for {rule_id}"

    if rule_id.startswith("isolate-") or ip_or_host in _state.isolated_hosts:
        _state.isolated_hosts.discard(ip_or_host)
        _state.rules.pop(rule_id, None)
        return True, f"rolled back isolation for {ip_or_host}"

    ip = ip_or_host
    if settings.soar_simulation_mode or not shutil.which("iptables"):
        _state.blocked_ips.discard(ip)
        _state.rules.pop(rule_id, None)
        return True, f"rolled back {rule_id}"

    try:
        subprocess.run(
            ["iptables", "-D", CHAIN_NAME, "-s", ip, "-j", "DROP"],
            capture_output=True, check=False,
        )
        _state.blocked_ips.discard(ip)
        _state.rules.pop(rule_id, None)
        return True, f"rolled back iptables rule for {ip}"
    except Exception as exc:
        return False, str(exc)


def verify_block(ip: str) -> bool:
    return ip in _state.blocked_ips
