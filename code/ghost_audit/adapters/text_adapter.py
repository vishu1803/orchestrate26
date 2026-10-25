"""Shift handovers and retained prose, without generic body substring identity matches."""
from dataclasses import replace
from ..models import ExtractionIssue
from ..normalization import make_observation


def parse(data, source):
    observations, issues = [], []
    lines = data.decode("utf-8-sig").splitlines()
    for number, line in enumerate(lines, 1):
        parts = [part.strip() for part in line.removeprefix("- ").split("|")]
        fields, kind = {"raw_line": line}, "RAW"
        if len(parts) == 6:
            timestamp, system, resource, category, result, subject = parts
            fields.update(timestamp=timestamp, system=system, resource_id=resource,
                          record_type=category, result=result, subject_reference=subject)
            kind = "READBACK"
        observation, errors = make_observation(fields, replace(source, locator=f"line:{number}"), kind=kind)
        observations.append(observation); issues.extend(errors)
    return observations, issues, {"lines": len(lines)}
