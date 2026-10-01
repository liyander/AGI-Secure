"""Optional, content-free OpenTelemetry export to an OTLP collector."""

from __future__ import annotations

import os

_tracer = None
_error = None


def status() -> dict:
    endpoint = os.getenv("AI_RANGE_OTLP_ENDPOINT", "").strip()
    return {"configured": bool(endpoint), "active": _tracer is not None, "endpoint": endpoint, "error": _error}


def _get_tracer():
    global _tracer, _error
    endpoint = os.getenv("AI_RANGE_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return None
    if _tracer is not None:
        return _tracer
    if _error is not None:
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        headers = {}
        for entry in os.getenv("AI_RANGE_OTLP_HEADERS", "").split(","):
            if "=" in entry:
                key, value = entry.split("=", 1)
                headers[key.strip()] = value.strip()
        provider = TracerProvider(resource=Resource.create({"service.name": "ai-security-range"}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, headers=headers)))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("ai-security-range")
    except ImportError:
        _error = "Install the optional observability packages in requirements-observability.txt."
    except Exception as exc:
        _error = f"OTLP setup failed: {type(exc).__name__}"
    return _tracer


def export_run(run: dict) -> None:
    tracer = _get_tracer()
    if not tracer:
        return
    with tracer.start_as_current_span("ai_security_range.run") as span:
        span.set_attribute("ai_range.run_id", run.get("run_id", ""))
        span.set_attribute("ai_range.scenario_id", run.get("scenario_id") or "custom")
        span.set_attribute("ai_range.protected", bool(run.get("protected")))
        span.set_attribute("ai_range.attack_success", bool(run.get("metrics", {}).get("attack_success")))
        for event in run.get("events", []):
            kind = event.get("event", "unknown")
            if kind in {"model_request", "tool_request", "tool_result", "policy_decision", "action_blocked", "state_change", "memory_quarantined", "approval_requested", "approval_decision", "monitor_alert"}:
                with tracer.start_as_current_span(f"ai_security_range.{kind}") as child:
                    child.set_attribute("ai_range.event_seq", int(event.get("seq", 0)))
                    if event.get("tool"):
                        child.set_attribute("ai_range.tool", str(event["tool"]))
                    if event.get("source"):
                        child.set_attribute("ai_range.guardrail", str(event["source"]))
                    if event.get("decision"):
                        child.set_attribute("ai_range.decision", str(event["decision"]))
