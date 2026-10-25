"""Local document/OCR proposals with locations; uncertain text never becomes state proof."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Protocol

from .identity import normalize_identifier
from .io import validate_manifest_path
from .models import EvidenceIdentifier, ExtractionResult, VisualDocument
from .normalization import freeze, make_observation


class VisualEvidenceExtractor(Protocol):
    def extract(self, result: ExtractionResult, dataset_root: Path | None) -> tuple[VisualDocument, ...]:
        """Return proposals, raw text, location and honest confidence/review flags."""
        ...


def candidates(text, locator):
    """Exact tokens only. Never repair OCR identifiers or infer owners from names."""
    found = []
    patterns = (("user_id", r"\buser_[A-Za-z0-9_-]+\b"),
                ("resource_id", r"\b(?:account|audit_record|support|attachment|export|connector|backup|archive|profile|search|analytics|legal_hold|tombstone|cache|contact|marketing)_[A-Za-z0-9_-]+\b"),
                ("email", r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
                ("business_reference", r"\b(?:ORD|CS|FIN)-[A-Za-z0-9-]+\b"))
    for field, pattern in patterns:
        for match in re.finditer(pattern, text):
            raw = match.group()
            normalized = normalize_identifier("email", raw) if field == "email" else raw
            found.append(EvidenceIdentifier(field, raw, normalized, f"{locator}/text:{match.start()}:{match.end()}"))
    return tuple(sorted(found, key=lambda i: (i.field, i.locator)))


class LocalDocumentExtractor:
    """Reuse extracted PDF pages; optional installed Windows OCR, no providers/network.

    OCR provides no calibrated confidence. All proposals need review, including
    identifier candidates: they may expose potentially relevant gaps, not facts.
    No OCR text is fed into the state normalizer.
    """
    def __init__(self, enable_ocr=True):
        self.enable_ocr = enable_ocr
        self.measurement = {"ocr_attempted": 0, "ocr_succeeded": 0, "ocr_failed": 0,
                            "ocr_seconds": 0.0, "model_calls": 0,
                            "pdf_raw_attempted": 0, "pdf_raw_succeeded": 0, "pdf_raw_failed": 0}

    def extract(self, result: ExtractionResult, dataset_root: Path | None = None) -> tuple[VisualDocument, ...]:
        if result.format == ".pdf":
            if not result.observations:
                return (self._document(replace(result.source, locator="document:full"), "", (), "none", ("pdf_extraction_failed",)),)
            if dataset_root is not None:
                self.measurement["pdf_raw_attempted"] += 1
                try:
                    path = validate_manifest_path(Path(dataset_root), result.source.file_path)
                    assert hashlib.sha256(path.read_bytes()).hexdigest() == result.source.content_sha256
                    executable = shutil.which("pdftotext")
                    if executable is None:
                        raise ValueError("pdftotext_unavailable")
                    raw = subprocess.run([executable, "-raw", "-enc", "UTF-8", str(path), "-"], capture_output=True, timeout=30)
                    if raw.returncode:
                        raise ValueError("pdf_raw_extraction_failed")
                    pages = raw.stdout.decode("utf-8").split("\f")
                    if pages and not pages[-1].strip():
                        pages.pop()
                    if len(pages) != len(result.observations) or hashlib.sha256(path.read_bytes()).hexdigest() != result.source.content_sha256:
                        raise ValueError("pdf_raw_source_or_page_mismatch")
                    self.measurement["pdf_raw_succeeded"] += 1
                    return tuple(self._document(o.source, text, (), "pdftotext:-raw", ("pdf_fields_and_observation_clock_require_review",))
                                 for o, text in zip(result.observations, pages))
                except (AssertionError, OSError, ValueError, subprocess.SubprocessError):
                    self.measurement["pdf_raw_failed"] += 1
            return tuple(self._document(o.source, o.attributes.get("text", ""), (), "pdftotext",
                                        ("pdf_fields_and_observation_clock_require_review",))
                         for o in result.observations)
        if result.format != ".png":
            return ()
        source = replace(result.source, locator="image:full")
        if not self.enable_ocr or dataset_root is None or os.name != "nt":
            return (self._document(source, "", (), "none", ("ocr_unavailable_or_not_enabled",)),)
        self.measurement["ocr_attempted"] += 1
        start = time.perf_counter()
        try:
            path = validate_manifest_path(Path(dataset_root), source.file_path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != source.content_sha256:
                raise ValueError("source_hash_mismatch")
            # Existing system policy permits inline local PowerShell; do not change
            # execution policy, install software, or pass source text as code.
            script = (Path(__file__).parent / "adapters/windows_ocr.ps1").read_text(encoding="utf-8")
            completed = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                       env={**os.environ, "GHOST_IMAGE_PATH": str(path)},
                                       capture_output=True, timeout=30)
            if completed.returncode:
                raise ValueError("local_ocr_failed")
            output = json.loads(completed.stdout.decode("utf-8-sig"))
            if not isinstance(output.get("text"), str) or not isinstance(output.get("lines"), list):
                raise ValueError("invalid_ocr_schema")
            if hashlib.sha256(path.read_bytes()).hexdigest() != source.content_sha256:
                raise ValueError("source_changed_during_ocr")
            self.measurement["ocr_succeeded"] += 1
            return (self._document(source, output["text"], tuple(output["lines"]), output["backend"],
                                   ("ocr_proposals_require_review", "ocr_clock_not_validated")),)
        except (OSError, ValueError, subprocess.SubprocessError):
            self.measurement["ocr_failed"] += 1
            return (self._document(source, "", (), "none", ("local_ocr_failed",)),)
        finally:
            self.measurement["ocr_seconds"] += time.perf_counter() - start

    @staticmethod
    def _document(source, text, regions, backend, issues):
        times = tuple(sorted(set(re.findall(r"\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)\b", text))))
        return VisualDocument(source, "text_extracted" if text.strip() else "review_required", text,
                              tuple(freeze(r) for r in regions), candidates(text, source.locator), times,
                              None, True, backend, issues if text.strip() else (*issues, "no_selectable_or_ocr_text"))


def document_inventory(documents):
    """No raw PII in routine diagnostics; exact candidate values remain in typed API."""
    return [{"file_id": d.source.evidence_id, "file_path": d.source.file_path,
             "locator": d.source.locator, "coverage": d.coverage, "backend": d.backend,
             "needs_review": d.needs_review, "confidence": d.confidence,
             "characters": len(d.raw_text), "region_lines": len(d.regions),
             "candidate_fields": sorted({i.field for i in d.candidates}),
             "resource_candidates": sorted({i.raw_value for i in d.candidates if i.field in {"resource_id", "business_reference"}}),
             "subject_candidate_count": sum(i.field in {"user_id", "email"} for i in d.candidates),
             "timestamp_candidates": list(d.time_candidates),
             "available_at": d.source.available_at.isoformat(), "issues": list(d.issues)} for d in documents]


def semantic_ledger(documents, evidence_index):
    """Located extraction proposals, without inventing screenshot state or clocks.

    Catalog links may corroborate exact resource/subject proposals; they do not
    validate OCR business semantics. Each page/image retains its own review flag.
    """
    known_resources = {o.resource_id for o in evidence_index.observations if o.resource_id}
    systems = {}
    from .state_facts import category, logical_system
    for o in evidence_index.observations:
        if o.resource_id:
            systems.setdefault(o.resource_id, set()).add((logical_system(o), category(o)))
    ledger = []
    for document in documents:
        resources = sorted({i.raw_value for i in document.candidates if i.field == "resource_id"})
        exact = [r for r in resources if r in known_resources]
        # Restrict inferred schema hints to exact participant record IDs; never
        # repair a confused OCR character or derive IDs from a case/user number.
        hints = sorted({pair for r in exact for pair in systems.get(r, ()) if pair[0] or pair[1]})
        ledger.append({"file_id": document.source.evidence_id, "file_path": document.source.file_path,
                       "locator": document.source.locator, "coverage": document.coverage,
                       "subject_ids": sorted({i.raw_value for i in document.candidates if i.field == "user_id"}),
                       "email_candidate_count": sum(i.field == "email" for i in document.candidates),
                       "resource_proposals": resources, "corroborated_resource_ids": exact,
                       "system_category_hints": hints, "observation_state": "UNKNOWN",
                       "observed_at": None, "available_at": document.source.available_at.isoformat(),
                       "time_proposals": list(document.time_candidates), "method": document.backend,
                       "confidence": document.confidence, "needs_review": True,
                       "issues": list(document.issues), "state_promoted": False})
        validated = [o for o in evidence_index.observations if o.source.evidence_id == document.source.evidence_id
                     and o.context.get("extraction_method") in {"content_labeled_raw_pdf_fields", "content_labeled_ocr_fields"}
                     and document.source.locator in o.context.get("document_pages", ())]
        if validated:
            row = ledger[-1]
            row.update(coverage="structured_fields_extracted", state_promoted=True,
                       resource_proposals=sorted({o.resource_id for o in validated}),
                       system_category_hints=sorted({(o.system_id, o.data_category) for o in validated}),
                       subject_ids=sorted({i.raw_value for o in validated for i in o.identifiers if i.field == "user_id"}),
                       observation_state="ACTIVE" if all(o.data_category == "DATA_FLOW" and o.attributes.get("enabled") is True for o in validated) else "PRESENT", observed_at=validated[0].observed_at.isoformat(),
                       provenance_locators=sorted({span for o in validated for span in
                                                   o.context.get("document_text_spans", (o.source.locator,))}),
                       needs_review=any(o.data_category == "SUPPORT_ATTACHMENT" or o.context.get("extraction_method") == "content_labeled_ocr_fields" for o in validated),
                       issues=(["exclusive_attachment_ownership_unknown"] if any(o.data_category == "SUPPORT_ATTACHMENT" for o in validated) else
                               ["selected_panel_extracted_other_rows_require_review"] if any(o.context.get("extraction_method") == "content_labeled_ocr_fields" for o in validated) else []))
    return tuple(ledger)


def validated_document_observations(documents):
    """Narrow content-labeled PDF schemas, never file/case-ID dispatch or OCR truth.

    Only raw-order selectable text is eligible. Ambiguous business references,
    incomplete human clocks and unrecognized schemas remain review gaps.
    """
    from collections import defaultdict
    from datetime import datetime, timezone
    grouped = defaultdict(list)
    for doc in documents:
        if doc.backend == "pdftotext:-raw":
            grouped[doc.source.evidence_id].append(doc)
    observations = []
    for pages in grouped.values():
        pages.sort(key=lambda d: d.source.locator)
        text = "\n".join(d.raw_text for d in pages)
        clocks = {}
        for m in re.finditer(r"\b(issued|recorded|captured|retain until)\s+(\d{1,2} [A-Za-z]{3} \d{4})\s+(\d{2})[ :](\d{2})\s+UTC\b", text, re.I):
            try:
                value = datetime.strptime(f"{m[2]} {m[3]}:{m[4]}", "%d %b %Y %H:%M").replace(tzinfo=timezone.utc)
                clocks.setdefault(m[1].lower(), []).append((value, m.group()))
            except ValueError:
                pass
        def clock(label):
            found = clocks.get(label, ())
            return found[0][0] if len({v for v, _ in found}) == 1 else None
        first = pages[0]
        attrs = None
        if "COMPLIANCE JOURNAL - SIGNED RECORD EXTRACT" in text:
            resources = set(re.findall(r"Event reference\s+(audit_record_[A-Za-z0-9_-]+)", text))
            users = set(re.findall(r"subject reference\s+(user_[A-Za-z0-9_-]+)", text))
            issued, recorded, until = clock("issued"), clock("recorded"), clock("retain until")
            if len(resources) == len(users) == 1 and issued and recorded and until and first.source.origin == "security_service":
                attrs = {"resource_id": next(iter(resources)), "subject_reference": next(iter(users)),
                         "system_id": first.source.origin, "record_type": "SECURITY_AUDIT_LOG", "result": "FOUND",
                         "observed_at": issued.isoformat(), "recorded_at": recorded.isoformat(), "retention_until": until.isoformat()}
        elif "Attachment properties and upload history" in text and "DELIVERY ADDRESS CORRECTION REQUEST" in text:
            resources = set(re.findall(r"Support reference\s+[^\n/]+/\s*(support_[A-Za-z0-9_-]+)", text))
            emails = set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text))
            captured = clock("captured")
            if len(resources) == len(emails) == 1 and captured and first.source.origin == "support_platform":
                attrs = {"resource_id": next(iter(resources)), "email": next(iter(emails)), "system_id": first.source.origin,
                         "record_type": "SUPPORT_ATTACHMENT", "result": "FOUND", "observed_at": captured.isoformat()}
                # One person on a document is not proof of exclusive attachment
                # ownership. That policy condition intentionally remains unknown.
        if attrs:
            spans = tuple(f"{d.source.locator}/text:0:{len(d.raw_text)}" for d in pages)
            source = replace(first.source, locator=";".join(spans))
            attrs["document_text"] = text
            observation, issues = make_observation(attrs, source, kind="READBACK",
                                                  context={"extraction_method": "content_labeled_raw_pdf_fields",
                                                           "document_pages": tuple(d.source.locator for d in pages),
                                                           "document_text_spans": spans,
                                                           "clock_text": tuple(raw for values in clocks.values() for _, raw in values)})
            if not issues:
                observations.append(observation)
    return tuple(observations)


class CachedDocumentExtractor:
    """Reuse an actual measured extraction pass when augmenting the shared index."""
    def __init__(self, documents, measurement):
        self.documents = tuple(documents)
        self.measurement = dict(measurement)

    def extract(self, result, dataset_root=None):
        return tuple(d for d in self.documents if d.source.evidence_id == result.source.evidence_id)


def validated_ocr_observations(documents, index, *, enable_support_context=False):
    """Located, corroborated selected-panel schemas; never identifier repair.

    Only exact OCR IDs with independent participant-source corroboration qualify.
    Corroboration availability is an additional cutoff, not future-state leakage.
    Activity confirms the literal ID only, never the resulting resource state.
    """
    from datetime import datetime, timezone
    from .state_facts import logical_system
    observations = []
    for document in documents:
        if document.backend != "Windows.Media.Ocr" or not document.regions:
            continue
        lines = []
        for number, region in enumerate(document.regions):
            words = region.get("words", ())
            if words:
                lines.append((str(region["text"]), min(w["x"] for w in words), min(w["y"] for w in words), number))
        def exact(text):
            return [line for line in lines if line[0].casefold() == text.casefold()]
        def card(label):
            anchors = [line for line in exact(label) if line[2] < 300]
            if len(anchors) != 1:
                return None
            anchor = anchors[0]
            values = [line for line in lines if 8 < line[2]-anchor[2] < 45 and abs(line[1]-anchor[1]) < 15]
            return min(values, key=lambda line:line[2]) if values else None
        def panel(label):
            anchors = [line for line in exact(label) if line[1] > 1000 and line[2] > 300]
            if len(anchors) != 1:
                return None
            anchor = anchors[0]
            values = [line for line in lines if line[1] > anchor[1]+50 and abs(line[2]-anchor[2]) < 8]
            return min(values,key=lambda line:line[1]) if values else None
        def clock(line):
            if line is None:
                return None
            match = re.search(r"\b(\d{1,2} [A-Za-z]{3} \d{4}) (\d{2}:\d{2}(?::\d{2})?) UTC\b",line[0],re.I)
            if not match:
                return None
            try:
                return datetime.strptime(match[1]+" "+match[2], "%d %b %Y %H:%M:%S" if match[2].count(":")==2 else "%d %b %Y %H:%M").replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        attrs = None
        used = []
        if "Customer Operations" in document.raw_text:
            # A captured customer-detail screen directly displays a profile.
            # Last contact/member-since are history, not the snapshot's clock.
            def account_tokens(line):
                found = set(re.findall(r"\baccount_[A-Za-z0-9_-]+\b", line[0]))
                words = document.regions[line[3]].get("words", ())
                for left, right in zip(words, words[1:]):
                    # OCR can segment one printed token into adjacent word boxes.
                    # Concatenate literal characters only; never fix l/1 or IDs.
                    gap = right["x"] - left["x"] - left["width"]
                    if left["text"] == "account" and re.fullmatch(r"_[A-Za-z0-9_-]+", right["text"]) and 0 <= gap <= 6 and abs(left["y"]-right["y"]) <= 4:
                        found.add(left["text"]+right["text"])
                return found
            headers = [line for line in lines if 120 < line[2] < 170
                       and re.search(r"\buser_[A-Za-z0-9_-]+\b", line[0]) and account_tokens(line)]
            email = card("Email")
            if len(headers) == 1 and email and re.fullmatch(r"[^@\s]+@[^@\s]+", email[0]):
                resources = account_tokens(headers[0])
                if len(resources) == 1:
                    # The email is the subject anchor. An OCR user token may be
                    # ambiguous and is preserved in raw text, never repaired.
                    attrs = {"resource_id": next(iter(resources)),
                             "email": email[0], "system_id": "account_service", "record_type": "USER_PROFILE",
                             "result": "FOUND", "observed_at": document.source.available_at.isoformat()}
                    used = [headers[0], email]
        elif enable_support_context and "Helpline Console" in document.raw_text and document.source.origin == "support_platform":
            # Only the selected ticket header and its displayed customer card
            # establish ownership. Order/agent context is local to this panel;
            # unrelated search results and conversation timestamps are not joins.
            headers = [line for line in lines if 120 < line[2] < 170 and line[1] > 220
                       and re.search(r"\bsupport_[A-Za-z0-9_-]+\b", line[0])]
            email = card("Email")
            orders = [line for line in lines if line[1] > 1400 and 315 < line[2] < 355
                      and re.fullmatch(r"order ORD-[A-Za-z0-9-]+", line[0], re.I)]
            conversation = [line for line in exact("Conversation") if 220 < line[1] < 400 and 315 < line[2] < 355]
            if len(headers) == len(orders) == len(conversation) == 1 and email and re.fullmatch(r"[^@\s]+@[^@\s]+", email[0]):
                resources = set(re.findall(r"\bsupport_[A-Za-z0-9_-]+\b", headers[0][0]))
                if len(resources) == 1:
                    # Capture dates the current ticket view. Undated wall-clock
                    # conversation entries are not substituted for snapshot time.
                    attrs = {"resource_id": next(iter(resources)), "email": email[0],
                             "system_id": document.source.origin, "record_type": "SUPPORT_MESSAGE",
                             "result": "FOUND", "shared_context": True,
                             "observed_at": document.source.available_at.isoformat(),
                             "order_context": orders[0][0]}
                    used = [headers[0], email, orders[0], conversation[0]]
        elif "BridgeOps" in document.raw_text:
            titles = [line for line in lines if line[1] > 1000 and 300 < line[2] < 370 and re.fullmatch(r"data_flow_[A-Za-z0-9_-]+",line[0])]
            selector, mode = panel("Selector"), panel("Sync mode")
            times = [line for line in lines if line[0].startswith("PRODUCTION") and clock(line)]
            if len(titles)==len(times)==1 and selector and mode and re.fullmatch(r"[^@\s]+@[^@\s]+",selector[0]) and re.sub(r"\s+","",mode[0]).casefold()=="continuoussync":
                attrs={"resource_id":titles[0][0],"system_id":"integration_service","record_type":"DATA_FLOW",
                       "subject_selector":selector[0],"enabled":True,"observed_at":clock(times[0]).isoformat()}
                used=[titles[0],selector,mode,times[0]]
        elif "Audience Operations" in document.raw_text:
            headers = [line for line in lines if 120 < line[2] < 170 and re.search(r"\bmarketing_[A-Za-z0-9_-]+\b",line[0])]
            refreshed=card("Last refreshed")
            if len(headers)==1 and clock(refreshed):
                ids=set(re.findall(r"\bmarketing_[A-Za-z0-9_-]+\b",headers[0][0]))
                emails=set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",headers[0][0]))
                if len(ids)==len(emails)==1:
                    attrs={"resource_id":next(iter(ids)),"system_id":"marketing_platform","record_type":"MARKETING_PROFILE",
                           "email":next(iter(emails)),"result":"FOUND","observed_at":clock(refreshed).isoformat()}
                    used=[headers[0],refreshed]
        if attrs is None:
            continue
        matches=[o for o in index.get_observations(attrs["resource_id"])
                 if logical_system(o)==attrs["system_id"] or o.attributes.get("target_system")==attrs["system_id"]]
        if not matches:
            continue
        corroboration=min(matches,key=lambda o:(max([o.source.available_at]+[t.value for t in o.timestamps if t.value]),o.source.evidence_id,o.source.locator))
        clocks=[corroboration.source.available_at, *([corroboration.observed_at] if corroboration.observed_at else []),
                *[t.value for t in corroboration.timestamps if t.value]]
        locator=document.source.locator+"/regions:"+",".join(str(line[3]) for line in used)
        attrs["document_text"]=document.raw_text
        observation,issues=make_observation(attrs,replace(document.source,locator=locator),kind="READBACK",
                       context={"extraction_method":"content_labeled_ocr_fields","document_pages":(document.source.locator,),
                                "document_text_spans":(locator,),"ocr_regions":tuple(document.regions[line[3]] for line in used),
                                "corroborating_source":(corroboration.source.evidence_id,corroboration.source.locator),
                                "ancestor_timestamps":tuple(("corroboration/"+str(n),value.isoformat()) for n,value in enumerate(clocks))})
        if not issues:
            observations.append(observation)
    return tuple(observations)
