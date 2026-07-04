"""Optional iptables integration for real perimeter blocking."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from aegis.config import settings

logger = logging.getLogger(__name__)

CHAIN_NAME = "AEGIS-BLOCK"


@dataclass
class FirewallState:
    blocked_ips: set[str] = field(default_factory=set)
    rules: dict[str, str] = field(default_factory=dict)


_state = FirewallState()


def is_iptables_available() -> bool:
    return shutil.which("iptables") is not None and not settings.soar_simulation_mode


def block_ip(ip: str) -> tuple[bool, str, str]:
    """Block IP via iptables. Returns (success, message, rule_id)."""
    rule_id = f"block-{ip.replace('.', '-')}"
    if settings.soar_simulation_mode:
        return True, f"[SIMULATED] blocked IP {ip}", rule_id

    if not is_iptables_available():
        _state.blocked_ips.add(ip)
        _state.rules[rule_id] = ip
        return True, f"[LOCAL-TRACKED] blocked IP {ip} (iptables unavailable)", rule_id

    try:
        subprocess.run(
            ["iptables", "-N", CHAIN_NAME],
            capture_output=True, check=False,
        )
        subprocess.run(
            ["iptables", "-I", "INPUT", "-j", CHAIN_NAME],
            capture_output=True, check=False,
        )
        result = subprocess.run(
            ["iptables", "-A", CHAIN_NAME, "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, check=True,
        )
        _state.blocked_ips.add(ip)
        _state.rules[rule_id] = ip
        logger.warning("iptables: blocked %s", ip)
        return True, f"blocked IP {ip} via iptables", rule_id
    except subprocess.CalledProcessError as exc:
        return False, f"iptables failed: {exc.stderr}", rule_id


def rollback_block(rule_id: str) -> tuple[bool, str]:
    ip = _state.rules.get(rule_id)
    if not ip:
        return True, f"no rule to rollback for {rule_id}"

    if settings.soar_simulation_mode or not is_iptables_available():
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
    if settings.soar_simulation_mode:
        return True
    return ip in _state.blocked_ips
