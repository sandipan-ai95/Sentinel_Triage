from __future__ import annotations

import os
from typing import Any, Dict

import httpx

from app.services.redaction import redact_alert_for_model


class OpenRouterJevProvider:
    endpoint = "https://openrouter.ai/api/alpha/decisions"

    def __init__(self, api_key: str | None = None, model: str = "typesafe/jev-1.13"):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.model = model or os.getenv("OPENROUTER_MODEL", "typesafe/jev-1.13")
        self.last_source = "mock"
        self.last_error = None

    def get_probabilities(self, alert: Dict[str, Any]) -> Dict[str, float]:
        if not self.api_key:
            return self._mock_probabilities()

        safe_alert = redact_alert_for_model(alert)
        questions = {
            "likely_false_positive": self._noul_question(
                "Is this alert likely to be a false positive?",
                "The alert is likely benign or expected.",
                "The alert indicates suspicious or malicious activity.",
            ),
            "needs_immediate_escalation": self._noul_question(
                "Does this alert need immediate analyst escalation?",
                "The alert should be escalated immediately for urgent human review.",
                "The alert does not need immediate escalation.",
            ),
            "needs_more_context": self._noul_question(
                "Does this alert need more context before disposition?",
                "Additional evidence or enrichment is needed before an analyst can decide.",
                "The available alert context is sufficient for analyst review.",
            ),
            "likely_related_to_existing_incident": self._noul_question(
                "Is this alert likely related to an existing incident?",
                "The alert likely belongs to an existing incident or activity grouping.",
                "The alert is likely independent of existing incidents.",
            ),
            "likely_requires_human_review": self._noul_question(
                "Does this alert require human review?",
                "A human analyst must review this alert before any disposition.",
                "The alert can be handled without human review.",
            ),
        }
        try:
            response = httpx.post(
                self.endpoint,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "http://localhost:8000",
                    "X-Title": "SOC Alert Triage",
                },
                json={
                    "model": self.model,
                    "questions": questions,
                    "state": safe_alert,
                },
                timeout=20.0,
            )
            response.raise_for_status()
            probabilities = self._parse_probabilities(response.json())
            self.last_source = "openrouter"
            self.last_error = None
            return probabilities
        except httpx.HTTPStatusError as error:
            self.last_source = "mock_fallback"
            self.last_error = f"http_{error.response.status_code}"
            return self._mock_probabilities()
        except httpx.TimeoutException:
            self.last_source = "mock_fallback"
            self.last_error = "timeout"
            return self._mock_probabilities()
        except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            self.last_source = "mock_fallback"
            self.last_error = type(error).__name__
            return self._mock_probabilities()

    @staticmethod
    def _mock_probabilities() -> Dict[str, float]:
        return {
            "likely_false_positive": 0.18,
            "needs_immediate_escalation": 0.52,
            "needs_more_context": 0.31,
            "likely_related_to_existing_incident": 0.44,
            "likely_requires_human_review": 0.81,
        }

    @staticmethod
    def _noul_question(instructions: str, true_criteria: str, false_criteria: str) -> Dict[str, Any]:
        return {
            "type": "noul",
            "instructions": instructions,
            "criteria": {"true": true_criteria, "false": false_criteria},
        }

    @staticmethod
    def _parse_probabilities(content: Dict[str, Any]) -> Dict[str, float]:
        answers = content["answers"]
        keys = (
            "likely_false_positive",
            "needs_immediate_escalation",
            "needs_more_context",
            "likely_related_to_existing_incident",
            "likely_requires_human_review",
        )
        if not all(key in answers for key in keys):
            raise ValueError("Jev response is missing required probability keys")
        return {key: round(min(1.0, max(0.0, float(answers[key]["noul"]))), 4) for key in keys}
