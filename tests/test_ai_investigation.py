from app.ai.service import ProviderError, validate_result


def test_ai_result_validation_accepts_structured_unknown():
    result = validate_result({"assessment":"UNKNOWN","confidence":0,"summary":"No verified evidence","evidence":[],"sources":[],"limitations":["No sources"]}, "mock")
    assert result["assessment"] == "UNKNOWN"


def test_ai_result_validation_rejects_invalid_assessment():
    try: validate_result({"assessment":"DEFINITELY_BAD","confidence":.5}, "mock")
    except ValueError: return
    assert False


def test_private_address_cannot_become_absolute_benign_assessment():
    result = validate_result({"assessment":"BENIGN","confidence":1,"summary":"private","evidence":[],"sources":[],"limitations":[]}, "mock", "IPV4", "192.168.56.6")
    assert result["assessment"] == "UNKNOWN"
    assert result["confidence"] <= .6
    assert "does not establish" in result["limitations"][-1]


def test_provider_error_is_structured_and_safe():
    error = ProviderError(503, "provider_unavailable", "Gemini service temporarily unavailable.", True, 4)
    assert error.data["status_code"] == 503
    assert error.data["retryable"] is True


def test_confidence_is_evidence_confidence_and_assessment_gets_limitation():
    result = validate_result({"assessment":"SUSPICIOUS","confidence":.8,"summary":"Observed behavior","evidence":[{"description":"Observed outbound connection","evidence_type":"behavioral"}],"sources":[],"limitations":[]}, "mock")
    assert result["confidence"] == .8
    assert result["limitations"]


def test_invalid_source_is_not_persisted_as_clickable_source():
    result = validate_result({"assessment":"UNKNOWN","confidence":.2,"summary":"No evidence","evidence":[],"sources":["javascript:alert(1)", "https://example.com/report"],"limitations":["No grounding"]}, "mock")
    assert result["sources"] == ["https://example.com/report"]


def test_private_ip_is_insufficient_for_benign_conclusion():
    result = validate_result({"assessment":"BENIGN","confidence":.99,"summary":"Private address","evidence":[],"sources":[],"limitations":[]}, "mock", "IPV4", "192.168.1.10")
    assert result["assessment"] == "UNKNOWN"
    assert result["confidence"] <= .6
