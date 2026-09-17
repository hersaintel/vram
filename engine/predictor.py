"""Deterministic predictor based on known event sequences."""

from __future__ import annotations

from models.observation import Observation
from models.prediction import Prediction
from models.hypothesis import Hypothesis


# Sequences use event_type strings produced by lab adapters (Keycloak/Wazuh/Postgres)
# and legacy simulator names. Matching is subsequence-based (order preserved).
KNOWN_SEQUENCES: list[tuple[list[str], str, float, str]] = [
    (
        ["authentication_success", "privilege_escalation"],
        "database_query",
        0.55,
        "After identity login and privilege escalation, sensitive database access often follows",
    ),
    (
        ["authentication_success", "privilege_escalation", "database_query"],
        "database_export",
        0.70,
        "Privileged session plus database access frequently precedes a large export",
    ),
    (
        ["privilege_escalation", "database_query", "database_export"],
        "external_connection",
        0.75,
        "Large export after privilege escalation raises likelihood of external transfer",
    ),
    (
        ["privilege_escalation", "database_export"],
        "external_connection",
        0.72,
        "Large sensitive export after privilege escalation often precedes outbound activity",
    ),
    (
        ["authentication_failure", "authentication_failure", "authentication_success"],
        "privilege_escalation",
        0.45,
        "Successful login after repeated failures may be followed by privilege abuse",
    ),
    (
        ["authentication_failure", "authentication_success"],
        "role_mapping",
        0.35,
        "Login after failures can precede role or privilege changes",
    ),
    # Legacy / older simulator names
    (
        ["vpn_login", "new_device", "privilege_escalation"],
        "database_access",
        0.55,
        "After VPN + new device + privilege escalation, database access often follows",
    ),
    (
        ["vpn_login", "new_device", "privilege_escalation", "database_access"],
        "database_export",
        0.70,
        "Sensitive database access after privilege escalation frequently precedes large exports",
    ),
    (
        ["privilege_escalation", "database_access", "database_export"],
        "external_connection",
        0.75,
        "Large export after privileged access raises likelihood of external transfer",
    ),
]


class Predictor:
    """Simple sequence-based predictor. No machine learning."""

    def predict(
        self,
        recent_events: list[Observation],
        active_hypotheses: list[Hypothesis],
    ) -> list[Prediction]:
        if not recent_events:
            return []

        # Oldest → newest among the most recent observations
        event_types = [o.event_type for o in reversed(recent_events[-20:])]

        # Also treat aliases so mixed naming still matches
        aliases = {
            "vpn_login": "authentication_success",
            "login": "authentication_success",
            "successful_login": "authentication_success",
            "database_access": "database_query",
            "db_query": "database_query",
            "postgres_query": "database_query",
            "large_export": "database_export",
            "data_export": "database_export",
            "outbound_connection": "external_connection",
            "exfil_channel": "external_connection",
            "network_connection": "external_connection",
            "login_error": "authentication_failure",
            "multiple_failed_logins": "authentication_failure",
        }
        normalised = [aliases.get(t, t) for t in event_types]

        predictions: list[Prediction] = []
        seen_predicted: set[str] = set()

        for sequence, predicted, base_conf, explanation in KNOWN_SEQUENCES:
            seq_norm = [aliases.get(s, s) for s in sequence]
            if not self._sequence_matches(normalised, seq_norm):
                continue
            # Skip predicting something that already occurred at the end of the window
            if predicted in normalised[-3:]:
                continue
            if predicted in seen_predicted:
                continue

            conf = base_conf
            for h in active_hypotheses:
                title = (h.title or "").lower()
                tags = h.tags or []
                if h.confidence > 0.6 and (
                    any(t in tags for t in ("exfiltration", "credential", "privilege"))
                    or "exfil" in title
                    or "credential" in title
                ):
                    conf = min(0.95, conf + 0.10)
                    break

            seen_predicted.add(predicted)
            predictions.append(
                Prediction(
                    predicted_event=predicted,
                    confidence=conf,
                    supporting_sequence=sequence,
                    explanation=explanation,
                    related_hypothesis_id=(
                        active_hypotheses[0].id if active_hypotheses else None
                    ),
                )
            )

        return predictions

    @staticmethod
    def _sequence_matches(recent: list[str], pattern: list[str]) -> bool:
        """True if pattern is an ordered (not necessarily contiguous) subsequence of recent."""
        if not pattern:
            return False
        it = iter(recent)
        return all(event in it for event in pattern)