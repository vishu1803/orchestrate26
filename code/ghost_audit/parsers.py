"""Read-only adapter dispatch: every source returns observations OR explicit diagnostics."""
from dataclasses import replace
import hashlib
from pathlib import Path
from .adapters import json_adapter, log_adapter, sql_adapter, text_adapter, visual_adapter
from .models import ExtractionIssue, ExtractionResult, ExtractionStatus, SourceRef
from .normalization import freeze

FORMAT_CANDIDATES = {
    ".json": "stdlib json + explicit nested adapters",
    ".sql": "isolated sqlite3 :memory: + SQL authorizer",
    ".log": "stdlib re/shlex + trace correlation",
    ".txt": "UTF-8 lines + delimited handover adapter",
    ".pdf": "pdftotext candidate; optional PDF library after fidelity tests",
    ".png": "image metadata + OCR candidate; selective optional VLM",
}


def parse_evidence(path: Path, source: SourceRef) -> ExtractionResult:
    """Account for failure/partial/metadata status; never reinterpret it as absence."""
    suffix = path.suffix.lower()
    try:
        if path.stat().st_size > 64_000_000:
            raise ValueError("evidence_file_budget_exceeded")
        data = path.read_bytes()
        source = replace(source, content_sha256=hashlib.sha256(data).hexdigest())
        dispatch = {".json": json_adapter.parse, ".sql": sql_adapter.parse,
                    ".log": log_adapter.parse, ".txt": text_adapter.parse}
        if suffix in dispatch:
            observations, issues, metadata = dispatch[suffix](data, source)
        elif suffix in {".pdf", ".png"}:
            observations, issues, metadata = getattr(visual_adapter, suffix[1:])(data, source, path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != source.content_sha256:
                raise ValueError("source_changed_during_extraction")
        else:
            return ExtractionResult(source, suffix, ExtractionStatus.UNSUPPORTED, (),
                                    (ExtractionIssue(source.evidence_id, "", "unsupported_format", "ERROR"),), freeze({}))
        status = ExtractionStatus.PARSED
        if suffix == ".png":
            status = ExtractionStatus.METADATA_ONLY
        elif issues:
            status = ExtractionStatus.PARTIAL
        return ExtractionResult(source, suffix, status, tuple(observations), tuple(issues), freeze(metadata))
    except Exception as exc:
        # Exception type/code only: parser errors must not echo SQL rows, document
        # text or personal identifiers into routine diagnostic summaries.
        code = str(exc) if isinstance(exc, (ValueError, ModuleNotFoundError)) and len(str(exc)) < 90 and " " not in str(exc) else type(exc).__name__
        return ExtractionResult(source, suffix, ExtractionStatus.FAILED, (),
                                (ExtractionIssue(source.evidence_id, "", "extraction_failed:" + code, "ERROR"),), freeze({}))
