"""Orchestrator — runs all 5 agents and assembles the final security report."""

from typing import Callable, Optional

from agents import (
    run_detection_agent,
    run_explainer_agent,
    run_mitigation_agent,
    run_rag_poisoning_agent,
    run_technique_classifier_agent,
)
from config import VERDICT_THRESHOLDS


AGENT_PIPELINE = [
    ("detection", "Detection Agent", run_detection_agent),
    ("technique", "Technique Classifier Agent", run_technique_classifier_agent),
    ("rag", "RAG Poisoning Agent", run_rag_poisoning_agent),
    ("explainer", "Explainer Agent", run_explainer_agent),
    ("mitigation", "Mitigation Agent", run_mitigation_agent),
]


def _compute_risk_score(results: dict) -> int:
    detection = results.get("detection", {})
    technique = results.get("technique", {})
    rag = results.get("rag", {})
    mitigation = results.get("mitigation", {})

    score = 0.0

    if detection.get("is_injection"):
        score += detection.get("confidence", 0) * 0.35
    else:
        score += (100 - detection.get("confidence", 50)) * 0.05

    technique_name = technique.get("technique", "none")
    if technique_name not in ("none", "other"):
        score += technique.get("confidence", 0) * 0.25
    elif technique_name == "other":
        score += technique.get("confidence", 0) * 0.15

    if rag.get("is_rag_threat"):
        score += rag.get("confidence", 0) * 0.20

    if mitigation.get("action") == "block":
        score += mitigation.get("confidence", 0) * 0.20
    elif mitigation.get("action") == "sanitize":
        score += mitigation.get("confidence", 0) * 0.10

    return min(100, max(0, int(round(score))))


def _determine_verdict(risk_score: int, mitigation: dict) -> str:
    if mitigation.get("action") == "block" and mitigation.get("confidence", 0) >= 70:
        return "BLOCK"

    for verdict, (low, high) in VERDICT_THRESHOLDS.items():
        if low <= risk_score <= high:
            return verdict
    return "BLOCK"


def run_analysis(
    prompt: str,
    api_key: str,
    model: str,
    on_agent_complete: Optional[Callable[[str, dict], None]] = None,
) -> dict:
    results: dict = {}

    for key, _name, agent_fn in AGENT_PIPELINE:
        if on_agent_complete:
            on_agent_complete(key, {"status": "running"})
        result = agent_fn(prompt, api_key, model)
        results[key] = result
        if on_agent_complete:
            on_agent_complete(key, result)

    risk_score = _compute_risk_score(results)
    mitigation = results.get("mitigation", {})
    verdict = _determine_verdict(risk_score, mitigation)

    return {
        "prompt": prompt,
        "overall_risk_score": risk_score,
        "verdict": verdict,
        "agents": {
            "detection": results.get("detection"),
            "technique": results.get("technique"),
            "rag_poisoning": results.get("rag"),
            "explainer": results.get("explainer"),
            "mitigation": results.get("mitigation"),
        },
    }


def build_report_from_results(prompt: str, results: dict) -> dict:
    risk_score = _compute_risk_score(results)
    mitigation = results.get("mitigation", {})
    verdict = _determine_verdict(risk_score, mitigation)
    return {
        "prompt": prompt,
        "overall_risk_score": risk_score,
        "verdict": verdict,
        "agents": {
            "detection": results.get("detection"),
            "technique": results.get("technique"),
            "rag_poisoning": results.get("rag"),
            "explainer": results.get("explainer"),
            "mitigation": results.get("mitigation"),
        },
    }


def get_agent_confidences(report: dict) -> list[dict]:
    agents = report.get("agents", {})
    confidences = []

    detection = agents.get("detection", {})
    confidences.append({
        "agent": "Detection",
        "confidence": detection.get("confidence", 0),
        "label": "Injection detected" if detection.get("is_injection") else "Clean",
    })

    technique = agents.get("technique", {})
    confidences.append({
        "agent": "Technique",
        "confidence": technique.get("confidence", 0),
        "label": technique.get("technique", "none"),
    })

    rag = agents.get("rag_poisoning", {})
    confidences.append({
        "agent": "RAG Poisoning",
        "confidence": rag.get("confidence", 0),
        "label": "RAG threat" if rag.get("is_rag_threat") else "No RAG threat",
    })

    mitigation = agents.get("mitigation", {})
    confidences.append({
        "agent": "Mitigation",
        "confidence": mitigation.get("confidence", 0),
        "label": mitigation.get("action", "unknown"),
    })

    return confidences