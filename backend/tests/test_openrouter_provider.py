from app.services.openrouter_provider import OpenRouterJevProvider


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "answers": {
                "likely_false_positive": {"noul": 0.1},
                "needs_immediate_escalation": {"noul": 0.8},
                "needs_more_context": {"noul": 0.2},
                "likely_related_to_existing_incident": {"noul": 0.4},
                "likely_requires_human_review": {"noul": 0.9},
            }
        }


def test_openrouter_provider_uses_redacted_alert(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs["json"]
        return FakeResponse()

    monkeypatch.setattr("app.services.openrouter_provider.httpx.post", fake_post)
    provider = OpenRouterJevProvider(api_key="test-key", model="test-model")

    probabilities = provider.get_probabilities({
        "rule_name": "suspicious_login",
        "user": "analyst.one",
        "source_ip": "198.51.100.12",
        "severity": "high",
    })

    assert captured["url"] == provider.endpoint
    state = captured["payload"]["state"]
    assert state["user"] == "[REDACTED]"
    assert state["source_ip"] == "[REDACTED]"
    assert captured["payload"]["questions"]["likely_false_positive"]["type"] == "noul"
    assert probabilities["needs_immediate_escalation"] == 0.8
    assert provider.last_source == "openrouter"
