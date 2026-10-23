from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


@dataclass(frozen=True, order=True)
class Issue:
    ref: str
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str
    category: str


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str


class ModelError(Exception):
    pass


STRIDE = ("S", "T", "R", "I", "D", "E")


def load_model(path: str | Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as file:
            model = yaml.safe_load(file)
    except (OSError, yaml.YAMLError) as exc:
        raise ModelError(str(exc)) from exc

    if not isinstance(model, dict):
        raise ModelError("Model must be a YAML mapping")

    for key in ("zones", "elements", "flows", "threats"):
        if model.get(key) is None:
            model[key] = []
        if not isinstance(model[key], list):
            raise ModelError(f"{key} must be a list")

    return model


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set(STRIDE)
    if kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"Unknown element kind: {kind}")


def validate(model: dict) -> list[Issue]:
    issues = set()
    zones = {z.get("id") for z in model["zones"]}
    elements = {e.get("id"): e for e in model["elements"]}
    flows = {f.get("id"): f for f in model["flows"]}
    seen = set()

    for section in ("zones", "elements", "flows", "threats"):
        for item in model[section]:
            item_id = item.get("id")
            if item_id is not None:
                if item_id in seen:
                    issues.add(Issue(item_id, "DUPLICATE_ID"))
                seen.add(item_id)

    for element in model["elements"]:
        ref = element.get("id", "")
        if element.get("kind") not in {
            "external_entity", "process", "data_store"
        }:
            issues.add(Issue(ref, "BAD_KIND"))
        if element.get("zone") not in zones:
            issues.add(Issue(ref, "UNKNOWN_ZONE"))

    for flow in model["flows"]:
        ref = flow.get("id", "")
        source_id = flow.get("source")
        target_id = flow.get("target")

        if source_id not in elements or target_id not in elements:
            issues.add(Issue(ref, "UNKNOWN_REF"))
        elif (
            source_id == target_id
            or (
                elements[source_id].get("kind") != "process"
                and elements[target_id].get("kind") != "process"
            )
        ):
            issues.add(Issue(ref, "INVALID_FLOW"))

    for threat in model["threats"]:
        ref = threat.get("id", "")
        target = threat.get("target")
        category = threat.get("category")
        status = threat.get("status")

        if target not in elements and target not in flows:
            issues.add(Issue(ref, "UNKNOWN_REF"))

        if category not in STRIDE:
            issues.add(Issue(ref, "BAD_CATEGORY"))
        elif target in elements:
            element = elements[target]
            try:
                allowed = applicable(
                    element.get("kind", ""),
                    is_log=element.get("is_log", False) is True,
                )
            except ValueError:
                allowed = set()

            if category not in allowed:
                issues.add(Issue(ref, "INAPPLICABLE_CATEGORY"))
        elif target in flows and category not in applicable("data_flow"):
            issues.add(Issue(ref, "INAPPLICABLE_CATEGORY"))

        for field in ("likelihood", "impact"):
            value = threat.get(field)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= 5
            ):
                issues.add(Issue(ref, "BAD_SCORE", field))

        if status not in {"open", "mitigated", "accepted"}:
            issues.add(Issue(ref, "BAD_STATUS"))
        elif status == "mitigated" and not str(
            threat.get("mitigation") or ""
        ).strip():
            issues.add(Issue(ref, "MISSING_MITIGATION"))
        elif status == "accepted" and not str(
            threat.get("justification") or ""
        ).strip():
            issues.add(Issue(ref, "MISSING_JUSTIFICATION"))

    return sorted(issues)


def crossing_flows(model: dict) -> list[str]:
    elements = {e.get("id"): e for e in model["elements"]}
    result = []

    for flow in model["flows"]:
        source = elements.get(flow.get("source"))
        target = elements.get(flow.get("target"))

        if source is None or target is None:
            continue

        if source.get("zone") != target.get("zone"):
            result.append(flow.get("id", ""))

    return result


def coverage_gaps(model: dict) -> list[Gap]:
    elements = {e.get("id"): e for e in model["elements"]}
    threats = model["threats"]
    gaps = set()

    for flow in model["flows"]:
        flow_id = flow.get("id")
        if flow_id not in crossing_flows(model):
            continue

        refs = [flow.get("source"), flow.get("target")]

        for ref in refs:
            element = elements[ref]
            categories = applicable(
                element.get("kind", ""),
                is_log=element.get("is_log", False) is True,
            )

            for category in categories:
                if not any(
                    threat.get("target") == ref
                    and threat.get("category") == category
                    for threat in threats
                ):
                    gaps.add(Gap(ref, category))

        for category in applicable("data_flow"):
            if not any(
                threat.get("target") == flow_id
                and threat.get("category") == category
                for threat in threats
            ):
                gaps.add(Gap(flow_id, category))

    order = {category: index for index, category in enumerate(STRIDE)}
    return sorted(gaps, key=lambda gap: (gap.ref, order[gap.category]))


def policy_findings(model: dict) -> list[Issue]:
    elements = {e.get("id"): e for e in model["elements"]}
    zones = {z.get("id"): z for z in model["zones"]}
    threats = model["threats"]
    findings = set()
    secure_protocols = {"https", "tls", "mtls", "sftp", "ssh"}
    crossing = set(crossing_flows(model))
    flows = {f.get("id"): f for f in model["flows"]}

    for flow_id in crossing:
        flow = flows[flow_id]
        protocol = str(flow.get("protocol") or "").lower()

        if protocol not in secure_protocols:
            findings.add(Issue(flow_id, "UNENCRYPTED_CROSSING"))

        source = elements.get(flow.get("source"))
        target = elements.get(flow.get("target"))

        if source is None or target is None:
            continue

        source_zone = zones.get(source.get("zone"), {})
        target_zone = zones.get(target.get("zone"), {})

        if (
            target_zone.get("trust", 0) > source_zone.get("trust", 0)
            and flow.get("authenticated") is not True
        ):
            findings.add(Issue(flow_id, "UNAUTHENTICATED_INBOUND"))

    for element in model["elements"]:
        if element.get("kind") != "data_store":
            continue
        if element.get("holds_pii") is not True:
            continue

        if not any(
            threat.get("target") == element.get("id")
            and threat.get("category") == "I"
            for threat in threats
        ):
            findings.add(
                Issue(element.get("id", ""), "PII_STORE_WITHOUT_I_THREAT")
            )

    return sorted(findings, key=lambda issue: (issue.ref, issue.code))


def rank(model: dict) -> list[RankedThreat]:
    ranked = []

    for threat in model["threats"]:
        if threat.get("status") != "open":
            continue

        likelihood = threat.get("likelihood")
        impact = threat.get("impact")

        if (
            not isinstance(likelihood, int)
            or isinstance(likelihood, bool)
            or not 1 <= likelihood <= 5
            or not isinstance(impact, int)
            or isinstance(impact, bool)
            or not 1 <= impact <= 5
        ):
            continue

        score = likelihood * impact
        level = "high" if score >= 15 else "medium" if score >= 8 else "low"

        ranked.append((RankedThreat(threat.get("id", ""), score, level), impact))

    def natural_id(value: str):
        return [
            int(part) if part.isdigit() else part.lower()
            for part in re.split(r"(\d+)", value)
        ]

    ranked.sort(
        key=lambda item: (
            -item[0].score,
            -item[1],
            natural_id(item[0].id),
        )
    )

    return [item[0] for item in ranked]