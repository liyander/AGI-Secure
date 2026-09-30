"""Small Presidio policy for synthetic email, phone, and account identifiers."""

from functools import lru_cache

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_anonymizer import AnonymizerEngine


@lru_cache(maxsize=1)
def _engines():
    recognizers = [
        PatternRecognizer(supported_entity="EMAIL_ADDRESS", patterns=[Pattern("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.9)]),
        PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[Pattern("phone", r"\b(?:\+1[-. ]?)?\d{3}[-. ]\d{3}[-. ]\d{4}\b", 0.8)]),
        PatternRecognizer(supported_entity="DEMO_ACCOUNT", patterns=[Pattern("demo_account", r"\bACCT-[A-Z0-9]{6,12}\b", 0.95)]),
    ]
    return recognizers, AnonymizerEngine()


def preview_redaction(text: str) -> dict:
    recognizers, anonymizer = _engines()
    findings = []
    for recognizer in recognizers:
        findings.extend(recognizer.analyze(text, entities=[recognizer.supported_entities[0]], nlp_artifacts=None))
    findings.sort(key=lambda item: (item.start, -item.score))
    result = anonymizer.anonymize(text=text, analyzer_results=findings)
    return {
        "sanitized": result.text,
        "entities": [{"type": item.entity_type, "start": item.start, "end": item.end, "confidence": round(item.score, 2)} for item in findings],
        "method": "Presidio PatternRecognizer + AnonymizerEngine; focused demo patterns, not general PII discovery.",
    }
