"""Snapshot-only SQLite loader: isolated memory, statement allowlist and authorizer."""
from dataclasses import replace
import re
import sqlite3
from .json_adapter import strict_json
from ..models import ExtractionIssue
from ..normalization import freeze, make_observation


def statements(text):
    buffer = ""
    for char in text:
        buffer += char
        if char == ";" and sqlite3.complete_statement(buffer):
            yield buffer
            buffer = ""
    remaining = re.sub(r"--[^\n]*|/\*.*?\*/", "", buffer, flags=re.S).strip()
    if remaining:
        raise ValueError("incomplete_sql_statement")


def topology(table):
    if "failover" in table:
        return "failover_replica"
    if "reporting" in table:
        return "reporting_replica"
    if "read_replica" in table:
        return "read_replica"
    if "replica_" in table:
        return "regional:" + table.split("replica_", 1)[1]
    if "primary" in table:
        return "primary"
    return None


def parse(data, source):
    text = data.decode("utf-8-sig")
    # Headers are source content; never derive capture/topology from file names.
    capture = re.search(r"(?mi)^--\s*Captured at:\s*(\S+)", text)
    header_topology = re.search(r"(?mi)^--\s*Database topology:\s*([^\r\n]+)", text)
    context = {"captured_at": capture.group(1)} if capture else {}
    observations, issues = [], []
    connection = sqlite3.connect(":memory:")
    connection.enable_load_extension(False)
    connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 16_000_000)
    connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16_000_000)
    steps = [0]

    def progress():
        steps[0] += 1000
        return steps[0] > 2_000_000

    allowed = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_READ,
               sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_TRANSACTION}

    def authorizer(action, arg1, arg2, database, trigger):
        # SQLite updates its own schema while creating tables. User UPDATE statements
        # are separately rejected. Functions, ATTACH, PRAGMA, triggers and virtual
        # tables are denied during untrusted loading.
        if action == sqlite3.SQLITE_CREATE_INDEX:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION:
            return sqlite3.SQLITE_OK if arg2 == "json_valid" else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA:
            return sqlite3.SQLITE_OK if arg1 == "foreign_keys" and str(arg2).lower() in {"on", "1"} else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_REINDEX:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and arg1 not in {"sqlite_master", "sqlite_schema"}:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

    connection.set_authorizer(authorizer)
    connection.set_progress_handler(progress, 1000)
    try:
        for statement in statements(text):
            cleaned = re.sub(r"--[^\n]*|/\*.*?\*/", "", statement, flags=re.S).strip()
            if not re.match(r"(?is)^(?:BEGIN(?:\s+TRANSACTION)?\s*;|COMMIT\s*;|CREATE\s+TABLE\s|CREATE\s+(?:UNIQUE\s+)?INDEX\s|INSERT\s+INTO\s|PRAGMA\s+foreign_keys\s*=\s*ON\s*;)", cleaned):
                raise ValueError("unsupported_or_unsafe_sql_statement")
            connection.execute(statement)
        connection.set_authorizer(None)
        connection.execute("PRAGMA query_only=ON")
        tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        scopes = []
        if "snapshot_scope" in tables:
            scope_columns = [r[1] for r in connection.execute('PRAGMA table_info("snapshot_scope")')]
            scopes = [dict(zip(scope_columns, row)) for row in connection.execute('SELECT * FROM "snapshot_scope" ORDER BY rowid')]
        total_rows = 0
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            schema = list(connection.execute("PRAGMA table_info(" + quoted + ")"))
            columns = [r[1] for r in schema]
            primary = [r[1] for r in sorted(schema, key=lambda r: r[5]) if r[5]]
            order = ",".join('"' + key.replace('"', '""') + '"' for key in primary) if primary else "rowid"
            cursor = connection.execute("SELECT * FROM " + quoted + " ORDER BY " + order)
            rows = cursor.fetchmany(200_001)
            if len(rows) > 200_000:
                raise ValueError("sql_row_budget_exceeded")
            total_rows += len(rows)
            topo = topology(table) or (header_topology.group(1).strip() if header_topology else None)
            if not rows:
                observation, errors = make_observation({"empty_table": True, "columns": columns}, replace(source, locator=f"table:{table}/empty"), context=context, collection=table, topology=topo)
                observation = replace(observation, raw_fields=freeze({}))
                observations.append(observation); issues.extend(errors)
            for number, values in enumerate(rows, 1):
                raw = dict(zip(columns, values))
                location = f"table:{table}/row:{number}"
                attrs = dict(raw)
                if isinstance(raw.get("record_json"), str):
                    try:
                        decoded = strict_json(raw["record_json"])
                        if not isinstance(decoded, dict):
                            raise ValueError
                        attrs["document"] = decoded
                    except (ValueError, TypeError):
                        issues.append(ExtractionIssue(source.evidence_id, location, "invalid_record_json", "ERROR"))
                row_context = {**context, "columns": tuple(columns), "table": table,
                               "primary_key": {key: raw[key] for key in primary}}
                relevant_scopes = [scope for scope in scopes if not raw.get("origin_system") or scope.get("origin_system") == raw["origin_system"]]
                row_context["snapshot_scope"] = tuple(scopes)
                row_context["ancestor_timestamps"] = tuple(("snapshot_scope/" + str(n) + "/captured_at", scope["captured_at"])
                                                           for n, scope in enumerate(relevant_scopes) if "captured_at" in scope)
                common_times = {scope["captured_at"] for scope in relevant_scopes if isinstance(scope.get("captured_at"), str)}
                if "captured_at" not in row_context and len(common_times) == 1:
                    row_context["captured_at"] = next(iter(common_times))
                observation, errors = make_observation(attrs, replace(source, locator=location), context=row_context, kind="METADATA" if table == "snapshot_scope" else "SNAPSHOT", collection=raw.get("collection_name", table), topology=topo)
                observation = replace(observation, raw_fields=freeze(raw), identifiers=tuple(
                    replace(identifier, locator=identifier.locator.replace("/document/", "/record_json#/"))
                    for identifier in observation.identifiers))
                # Original embedded JSON string remains present; parsed document is separate.
                observations.append(observation); issues.extend(errors)
        return observations, issues, {"tables": tuple(tables), "rows": total_rows}
    finally:
        connection.close()
