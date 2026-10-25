"""Nested JSON records, service exports and empty scoped snapshots with JSON pointers."""
import json
from dataclasses import replace
from ..models import ExtractionIssue
from ..normalization import TIME_KEYS, freeze, make_observation, pointer_child


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonstandard_json_constant")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def parse(data, source):
    root = strict_json(data.decode("utf-8-sig"))
    observations, issues = [], []

    def emit(raw, location, context, kind="SNAPSHOT"):
        if kind == "SNAPSHOT" and ("status_code" in raw or context.get("collection") in {"profile_lookups", "index_queries"}):
            kind = "READBACK"
        observation, errors = make_observation(raw, replace(source, locator=location), context=context, kind=kind)
        observations.append(observation); issues.extend(errors)

    def walk(value, location, context, record=False):
        if isinstance(value, dict):
            inherited = dict(context)
            ancestors = list(context.get("ancestor_timestamps", ()))
            for key in TIME_KEYS:
                if key in value:
                    # Preserve distinct outer export vs inner capture/record clocks.
                    inherited[key] = value[key]
                    ancestors.append((pointer_child(location, key), value[key]))
            inherited["ancestor_timestamps"] = tuple(ancestors)
            for key in ("collection", "data_store", "region", "shard", "topology"):
                if key in value:
                    inherited[key] = value[key]
            if isinstance(value.get("system_id"), str):
                inherited["system_id"] = value["system_id"]
            if record or "resource_id" in value:
                emit(value, location, context)
                for key in ("resources", "records"):
                    if key in value:
                        walk(value[key], pointer_child(location, key), inherited, True)
                return
            found = False
            for key, child in value.items():
                path = pointer_child(location, key)
                if key == "service_exports" and isinstance(child, dict):
                    found = True
                    for system, collections in child.items():
                        system_path = pointer_child(path, system)
                        if not isinstance(collections, dict):
                            emit({"unparsed_value": collections}, system_path, inherited, "RAW")
                            issues.append(ExtractionIssue(source.evidence_id, system_path, "unexpected_service_container", "ERROR"))
                            continue
                        for collection, items in collections.items():
                            walk(items, pointer_child(system_path, collection), {**inherited, "system_id": system, "collection": collection}, True)
                elif isinstance(child, (dict, list)):
                    found = True
                    walk(child, path, inherited, key in {"records", "resources"})
            if not found:
                emit(value, location, inherited, "RAW")
                issues.append(ExtractionIssue(source.evidence_id, location, "unrecognized_json_object", "WARNING"))
        elif isinstance(value, list):
            if not value:
                emit({"empty_collection": True, "records": []}, location, context)
                observations[-1] = replace(observations[-1], raw_fields=freeze(value))
            for index, item in enumerate(value):
                walk(item, pointer_child(location, index), context, record)
        else:
            emit({"raw_value": value}, location, context, "RAW")
            observations[-1] = replace(observations[-1], raw_fields=freeze(value))
            issues.append(ExtractionIssue(source.evidence_id, location, "nonrecord_json_value", "WARNING"))
    walk(root, "", {})
    return observations, issues, {"root_type": type(root).__name__}
