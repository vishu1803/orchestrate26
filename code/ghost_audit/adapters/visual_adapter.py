"""Selectable per-page PDF text and validated PNG metadata; visual semantics deferred."""
from dataclasses import replace
from io import BytesIO
import json
import os
import shutil
import struct
import subprocess

from ..models import ExtractionIssue
from ..normalization import make_observation


def pdf(data, source, path):
    if not data.startswith(b"%PDF-"):
        raise ValueError("invalid_pdf_header")
    executable = shutil.which("pdftotext")
    if executable is None:
        raise ModuleNotFoundError("pdftotext")
    result = subprocess.run([executable, "-layout", "-enc", "UTF-8", str(path), "-"], capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("pdf_text_extraction_failed")
    pages = result.stdout.decode("utf-8").split("\f")
    if pages and pages[-1] == "":
        pages.pop()
    pages = pages or [""]
    observations, issues = [], []
    for page, text in enumerate(pages, 1):
        location = f"page:{page}"
        empty = not text.strip()
        observation, errors = make_observation({"text": text, "page_number": page}, replace(source, locator=location), kind="METADATA" if empty else "RAW")
        observations.append(observation); issues.extend(errors)
        if empty:
            issues.append(ExtractionIssue(source.evidence_id, location, "visual_extraction_required", "DEFERRED"))
    return observations, issues, {"pages": len(pages), "backend": "pdftotext", "semantic_fields_extracted": False}


def decode_png(path, data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("invalid_png_signature")
    try:
        from PIL import Image
    except ImportError:
        if os.name != "nt":
            raise ModuleNotFoundError("Pillow or Windows System.Drawing required")
        environment = {**os.environ, "GHOST_IMAGE_PATH": str(path.resolve())}
        script = '''$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Drawing;
$i=[System.Drawing.Image]::FromFile($env:GHOST_IMAGE_PATH);
try { $b=New-Object System.Drawing.Bitmap($i); try {
$null=$b.GetPixel(0,0); @{width=$i.Width;height=$i.Height;mode=$i.PixelFormat.ToString();backend='System.Drawing'} | ConvertTo-Json -Compress
} finally {$b.Dispose()} } finally {$i.Dispose()}'''
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                env=environment, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError("png_decode_failed")
        return json.loads(result.stdout.decode("utf-8-sig"))
    with Image.open(BytesIO(data)) as image:
        if image.format != "PNG":
            raise ValueError("not_png")
        image.verify()
    with Image.open(BytesIO(data)) as image:
        image.load()
        return {"width": image.width, "height": image.height, "mode": image.mode, "backend": "Pillow"}


def png(data, source, path):
    metadata = decode_png(path, data)
    observation, issues = make_observation(metadata, replace(source, locator="image:full"), kind="METADATA")
    issues.append(ExtractionIssue(source.evidence_id, "image:full", "visual_extraction_deferred", "DEFERRED"))
    return [observation], issues, metadata
