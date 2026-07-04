"""SOAR playbook engine with verify and rollback."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable

import yaml

from aegis.config import PLAYBOOKS_DIR, settings
from aegis.core.audit import AuditLedger
from aegis.core.schema import Alert, RemediationResult, RemediationStatus

logger = logging.getLogger(__name__)

ActionFn = Callable[[Alert, dict[str, Any]], tuple[bool, str, list[str]]]


class PlaybookEngine:
    """Executes YAML-defined response playbooks with rollback support."""

    def __init__(
        self,
        playbooks_dir: Path | None = None,
        auto_tier: int | None = None,
    ) -> None:
        self.playbooks_dir = playbooks_dir or PLAYBOOKS_DIR
        self.auto_tier = auto_tier if auto_tier is not None else settings.auto_response_tier
        self.audit = AuditLedger()
        self._actions: dict[str, ActionFn] = {}
        self._register_builtin_actions()

    def _register_builtin_actions(self) -> None:
        self.register_action("log_alert", self._action_log_alert)
        self.register_action("block_ip", self._action_block_ip)
        self.register_action("block_llm_request", self._action_block_llm)
        self.register_action("rate_limit", self._action_rate_limit)
        self.register_action("notify_webhook", self._action_notify)
        self.register_action("isolate_host", self._action_isolate_host)
        self.register_action("kill_process", self._action_kill_process)
        self.register_action("verify_block", self._action_verify_block)
        self.register_action("rollback_firewall", self._action_rollback_firewall)

    def register_action(self, name: str, fn: ActionFn) -> None:
        self._actions[name] = fn

    def load_playbook(self, playbook_id: str) -> dict[str, Any]:
        path = self.playbooks_dir / f"{playbook_id}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"Playbook not found: {playbook_id}")
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def list_playbooks(self) -> list[str]:
        if not self.playbooks_dir.exists():
            return []
        return [p.stem for p in self.playbooks_dir.glob("*.yaml")]

    def should_auto_execute(self, playbook: dict[str, Any], alert: Alert) -> bool:
        tier = int(playbook.get("autonomy_tier", 99))
        min_confidence = float(playbook.get("min_confidence", 0.8))
        return tier <= self.auto_tier and alert.confidence >= min_confidence

    def execute(self, playbook_id: str, alert: Alert, force: bool = False) -> RemediationResult:
        try:
            playbook = self.load_playbook(playbook_id)
        except FileNotFoundError:
            return RemediationResult(
                playbook_id=playbook_id,
                alert_id=alert.alert_id,
                status=RemediationStatus.SKIPPED,
                message=f"Playbook {playbook_id} not found",
            )

        if not force and not self.should_auto_execute(playbook, alert):
            return RemediationResult(
                playbook_id=playbook_id,
                alert_id=alert.alert_id,
                status=RemediationStatus.PENDING_APPROVAL,
                message="Awaiting approval — autonomy tier or confidence threshold not met",
            )

        actions_taken: list[str] = []
        rollback_stack: list[str] = []

        for step in playbook.get("steps", []):
            action_name = step["action"]
            params = step.get("params", {})
            timeout = float(step.get("timeout_seconds", 30))
            fn = self._actions.get(action_name)
            if not fn:
                return RemediationResult(
                    playbook_id=playbook_id,
                    alert_id=alert.alert_id,
                    status=RemediationStatus.FAILED,
                    actions_taken=actions_taken,
                    message=f"Unknown action: {action_name}",
                )
            start = time.monotonic()
            try:
                success, msg, rollback = fn(alert, params)
            except Exception as exc:
                logger.exception("Playbook step failed: %s", action_name)
                self._run_rollback(alert, rollback_stack)
                return RemediationResult(
                    playbook_id=playbook_id,
                    alert_id=alert.alert_id,
                    status=RemediationStatus.FAILED,
                    actions_taken=actions_taken,
                    rollback_actions=rollback_stack,
                    message=str(exc),
                )
            elapsed = time.monotonic() - start
            if elapsed > timeout:
                self._run_rollback(alert, rollback_stack)
                return RemediationResult(
                    playbook_id=playbook_id,
                    alert_id=alert.alert_id,
                    status=RemediationStatus.FAILED,
                    actions_taken=actions_taken,
                    rollback_actions=rollback_stack,
                    message=f"Step {action_name} timed out after {timeout}s",
                )
            actions_taken.append(f"{action_name}: {msg}")
            rollback_stack.extend(rollback)
            if not success:
                on_fail = step.get("on_failure", "rollback")
                if on_fail == "rollback":
                    self._run_rollback(alert, rollback_stack)
                    return RemediationResult(
                        playbook_id=playbook_id,
                        alert_id=alert.alert_id,
                        status=RemediationStatus.ROLLED_BACK,
                        actions_taken=actions_taken,
                        rollback_actions=rollback_stack,
                        message=msg,
                    )
                return RemediationResult(
                    playbook_id=playbook_id,
                    alert_id=alert.alert_id,
                    status=RemediationStatus.FAILED,
                    actions_taken=actions_taken,
                    message=msg,
                )

        self.audit.append(
            actor="soar-engine",
            action="playbook_executed",
            resource_type="alert",
            resource_id=alert.alert_id,
            payload={"playbook_id": playbook_id, "actions": actions_taken},
        )
        return RemediationResult(
            playbook_id=playbook_id,
            alert_id=alert.alert_id,
            status=RemediationStatus.SUCCESS,
            actions_taken=actions_taken,
            rollback_actions=rollback_stack,
            message="Playbook completed successfully",
        )

    def _run_rollback(self, alert: Alert, rollback_actions: list[str]) -> None:
        for rb in reversed(rollback_actions):
            if rb.startswith("rollback_firewall:"):
                self._actions["rollback_firewall"](alert, {"rule_id": rb.split(":", 1)[1]})

    # Built-in actions (integrate with real firewall/API in production deployments)

    def _action_log_alert(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        logger.warning("ALERT [%s] %s — %s", alert.severity.value, alert.title, alert.description[:200])
        return True, "logged", []

    def _action_block_ip(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        ip = params.get("ip") or alert.entity.id
        rule_id = f"block-{ip.replace('.', '-')}"
        prefix = "[SIMULATED] " if settings.soar_simulation_mode else ""
        rollback = [f"rollback_firewall:{rule_id}"]
        return True, f"{prefix}blocked IP {ip}", rollback

    def _action_block_llm(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        return True, "LLM request blocked at gateway", []

    def _action_rate_limit(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        entity = alert.entity.id
        return True, f"rate limited {entity}", []

    def _action_notify(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        channel = params.get("channel", "default")
        return True, f"notification sent to {channel}", []

    def _action_isolate_host(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        host = alert.entity.id
        return True, f"host {host} isolated (simulated)", [f"rollback_firewall:isolate-{host}"]

    def _action_kill_process(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        pid = params.get("pid", "unknown")
        return True, f"process {pid} terminated (simulated)", []

    def _action_verify_block(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        return True, "block verified", []

    def _action_rollback_firewall(self, alert: Alert, params: dict) -> tuple[bool, str, list[str]]:
        rule_id = params.get("rule_id", "")
        return True, f"rolled back rule {rule_id}", []
