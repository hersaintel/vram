"""Deterministic reasoning rules.

Rules contribute evidence to hypotheses; they never emit final conclusions.
Cross-source aware: Keycloak, Wazuh, and PostgreSQL events all feed the same hypotheses.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from models.observation import Observation


@dataclass
class RuleResult:
    """Evidence contributed by a single rule."""

    hypothesis_title: str
    delta: float
    reason: str
    tags: list[str]


def _has_prior(
    context: list[Observation],
    event_types: set[str],
    user: str | None,
    within_minutes: int = 60,
    current: Observation | None = None,
) -> bool:
    if not user:
        return False
    cutoff = None
    if current is not None:
        cutoff = current.timestamp - timedelta(minutes=within_minutes)
    for o in context:
        if o.user != user:
            continue
        if o.event_type not in event_types:
            continue
        if cutoff and o.timestamp < cutoff:
            continue
        return True
    return False


class RuleEngine:
    """Collection of modular, explainable rules."""

    def __init__(self) -> None:
        self._rules: list[Callable[[Observation, list[Observation]], list[RuleResult]]] = []
        self._register_default_rules()

    def _register_default_rules(self) -> None:
        self._rules.append(self._rule_auth_success)
        self._rules.append(self._rule_auth_failure)
        self._rules.append(self._rule_new_ip_or_device)
        self._rules.append(self._rule_privilege_escalation)
        self._rules.append(self._rule_role_mapping)
        self._rules.append(self._rule_database_access)
        self._rules.append(self._rule_large_export)
        self._rules.append(self._rule_external_connection)
        self._rules.append(self._rule_mfa_verified)
        self._rules.append(self._rule_normal_activity)
        self._rules.append(self._rule_cross_source_boost)
        self._rules.append(self._rule_post_mfa_cooling)

    def evaluate(
        self,
        observation: Observation,
        context: list[Observation],
    ) -> list[RuleResult]:
        results: list[RuleResult] = []
        for rule in self._rules:
            results.extend(rule(observation, context))
        return results

    # --- Identity / authentication ---

    def _rule_auth_success(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in (
            "authentication_success", "vpn_login", "login", "successful_login"
        ):
            return []
        results = [
            RuleResult(
                hypothesis_title="Possible Credential Abuse",
                delta=0.10,
                reason=f"Successful authentication via {obs.source}",
                tags=["authentication", obs.source],
            )
        ]
        # Login after recent failures is more suspicious
        if _has_prior(context, {"authentication_failure", "multiple_failed_logins"}, obs.user, 30, obs):
            results.append(
                RuleResult(
                    hypothesis_title="Possible Credential Abuse",
                    delta=0.18,
                    reason="Successful login after recent authentication failures",
                    tags=["authentication", "failure"],
                )
            )
        return results

    def _rule_auth_failure(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in (
            "authentication_failure", "multiple_failed_logins", "login_error"
        ):
            return []
        delta = 0.12 if obs.event_type == "multiple_failed_logins" else 0.08
        return [
            RuleResult(
                hypothesis_title="Possible Credential Abuse",
                delta=delta,
                reason=f"Authentication failure via {obs.source}",
                tags=["authentication", "failure", obs.source],
            )
        ]

    def _rule_new_ip_or_device(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type in ("new_device", "unknown_device") or "new_device" in (obs.tags or []):
            return [
                RuleResult(
                    hypothesis_title="Possible Credential Abuse",
                    delta=0.16,
                    reason="Activity from previously unseen device",
                    tags=["authentication", "device"],
                )
            ]
        # Heuristic: first-seen source_ip for this user in context
        if obs.source_ip and obs.user and obs.event_type in (
            "authentication_success", "vpn_login", "login"
        ):
            prior_ips = {
                o.source_ip for o in context
                if o.user == obs.user and o.source_ip and o.id != obs.id
            }
            if prior_ips and obs.source_ip not in prior_ips:
                return [
                    RuleResult(
                        hypothesis_title="Possible Credential Abuse",
                        delta=0.14,
                        reason=f"Login from new source IP {obs.source_ip}",
                        tags=["authentication", "new_ip"],
                    )
                ]
        return []

    def _rule_privilege_escalation(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in (
            "privilege_escalation", "sudo", "admin_granted", "impersonation"
        ):
            return []
        return [
            RuleResult(
                hypothesis_title="Possible Credential Abuse",
                delta=0.20,
                reason=f"Privilege escalation detected via {obs.source}",
                tags=["privilege", obs.source],
            ),
            RuleResult(
                hypothesis_title="Possible PHI Exfiltration",
                delta=0.22,
                reason="Privilege escalation may enable sensitive data access",
                tags=["privilege", "exfiltration"],
            ),
        ]

    def _rule_role_mapping(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in ("role_mapping", "database_privilege"):
            return []
        return [
            RuleResult(
                hypothesis_title="Possible Credential Abuse",
                delta=0.15,
                reason=f"Role / privilege mapping change via {obs.source}",
                tags=["privilege", "role", obs.source],
            )
        ]

    # --- Database ---

    def _rule_database_access(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in (
            "database_query", "database_access", "db_query", "postgres_query",
            "database_write", "database_connect",
        ):
            return []
        delta = 0.12
        reason = f"Database activity via {obs.source}"
        if "sensitive_data" in (obs.tags or []):
            delta = 0.20
            reason = f"Sensitive database access ({obs.metadata.get('table', 'unknown table')})"
        results = [
            RuleResult(
                hypothesis_title="Possible PHI Exfiltration",
                delta=delta,
                reason=reason,
                tags=["database", obs.source],
            )
        ]
        # Boost if recent suspicious auth — but not if MFA recently verified
        if _has_prior(
            context,
            {"authentication_success", "vpn_login", "privilege_escalation", "authentication_failure"},
            obs.user,
            30,
            obs,
        ) and not _has_prior(
            context,
            {"mfa_verified"},
            obs.user,
            30,
            obs,
        ):
            results.append(
                RuleResult(
                    hypothesis_title="Possible PHI Exfiltration",
                    delta=0.10,
                    reason="Database access following recent authentication / privilege activity",
                    tags=["database", "correlation"],
                )
            )
        return results

    def _rule_large_export(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in ("database_export", "large_export", "data_export"):
            if "export" not in (obs.tags or []) and "large_query" not in (obs.tags or []):
                return []
            # large_query on sensitive table still counts
            if "large_query" not in (obs.tags or []):
                return []
        rows = obs.metadata.get("rows") or 0
        delta = 0.22
        if isinstance(rows, int) and rows >= 10000:
            delta = 0.28
        return [
            RuleResult(
                hypothesis_title="Possible PHI Exfiltration",
                delta=delta,
                reason=f"Large database export/query ({rows} rows)" if rows else "Large database export observed",
                tags=["database", "export", obs.source],
            )
        ]

    def _rule_external_connection(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in (
            "external_connection", "outbound_connection", "exfil_channel", "network_connection"
        ):
            return []
        # Only strong if prior sensitive activity
        if not _has_prior(
            context,
            {"database_export", "database_query", "database_access", "privilege_escalation"},
            obs.user,
            60,
            obs,
        ):
            return [
                RuleResult(
                    hypothesis_title="Possible PHI Exfiltration",
                    delta=0.05,
                    reason="Network connection observed",
                    tags=["network"],
                )
            ]
        return [
            RuleResult(
                hypothesis_title="Possible PHI Exfiltration",
                delta=0.15,
                reason="External/network connection after sensitive database or privilege activity",
                tags=["network", "exfiltration", obs.source],
            )
        ]

    def _rule_mfa_verified(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in ("mfa_verified", "mfa_success") and "mfa" not in (obs.tags or []):
            return []
        return [
            RuleResult(
                hypothesis_title="Possible Credential Abuse",
                delta=-0.30,
                reason="MFA verification is a mitigating signal (not proof of legitimacy)",
                tags=["authentication", "mfa"],
            ),
            RuleResult(
                hypothesis_title="Possible PHI Exfiltration",
                delta=-0.22,
                reason="MFA verification is a mitigating signal",
                tags=["authentication", "mfa"],
            ),
        ]

    def _rule_normal_activity(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        if obs.event_type not in (
            "normal_business_activity", "expected_access", "logout",
            "application_access", "file_access",
        ):
            return []
        return [
            RuleResult(
                hypothesis_title="Possible Credential Abuse",
                delta=-0.20,
                reason="Activity consistent with normal business behavior",
                tags=["benign"],
            ),
            RuleResult(
                hypothesis_title="Possible PHI Exfiltration",
                delta=-0.25,
                reason="Activity consistent with normal business behavior",
                tags=["benign"],
            ),
        ]

    def _rule_cross_source_boost(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        """Extra evidence when multiple independent sources describe the same user."""
        if not obs.user:
            return []
        sources = {o.source for o in context if o.user == obs.user}
        sources.add(obs.source)
        if len(sources) < 2:
            return []
        # Only boost on meaningful events
        if _has_prior(context, {"mfa_verified"}, obs.user, 30, obs):
            return []  # do not amplify after MFA
        if obs.event_type in (
            "database_export", "privilege_escalation", "external_connection",
        ) or (obs.event_type == "database_query" and "sensitive_data" in (obs.tags or [])):
            return [
                RuleResult(
                    hypothesis_title="Possible PHI Exfiltration",
                    delta=0.08,
                    reason=f"Cross-source correlation ({', '.join(sorted(sources))})",
                    tags=["correlation"],
                )
            ]
        return []

    def _rule_post_mfa_cooling(
        self, obs: Observation, context: list[Observation]
    ) -> list[RuleResult]:
        """After MFA, subsequent low-risk activity cools hypotheses more aggressively.

        No external connection + MFA + normal/small DB access → stronger dismissal signal.
        """
        if not obs.user:
            return []
        if not _has_prior(context, {"mfa_verified"}, obs.user, 45, obs):
            return []
        # External connection still pending would block cooling
        if _has_prior(context, {"external_connection", "exfil_channel"}, obs.user, 60, obs):
            return []
        if obs.event_type in (
            "database_query", "database_access", "logout",
            "normal_business_activity", "expected_access", "file_access",
            "application_access",
        ):
            rows = obs.metadata.get("rows") or 0
            if isinstance(rows, int) and rows >= 10000:
                return []  # still large — do not cool
            if "sensitive_data" in (obs.tags or []) and "export" in (obs.tags or []):
                return []
            return [
                RuleResult(
                    hypothesis_title="Possible Credential Abuse",
                    delta=-0.18,
                    reason="Post-MFA low-risk activity reduces credential-abuse suspicion",
                    tags=["benign", "mfa", "cooling"],
                ),
                RuleResult(
                    hypothesis_title="Possible PHI Exfiltration",
                    delta=-0.20,
                    reason="Post-MFA activity without external transfer reduces exfiltration suspicion",
                    tags=["benign", "mfa", "cooling"],
                ),
            ]
        return []
