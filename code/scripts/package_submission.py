"""Phase 6 reproducible packaging; Phase 0 dry-run contract preserved."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

EXCLUDED_PARTS = {"dataset", ".git", ".venv", "venv", "node_modules", "__pycache__",
                  ".pytest_cache", ".cache", "tmp", "dist", "build", "agent-trace"}
ARCHIVES = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"}


def package_plan(root: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Flatten source code/ into archive root so evaluation/ paths match AGENTS."""
    included, excluded = [], []
    code_root = (root / "code").resolve()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts or not path.is_file():
            continue
        source = relative.as_posix()
        safe = not any(part in EXCLUDED_PARTS or part.startswith(".env") for part in relative.parts)
        safe = safe and not path.is_symlink() and path.suffix.lower() not in ARCHIVES
        allowed = (relative.parts[0] == "code" and path.resolve().is_relative_to(code_root)
                   and (path.suffix in {".py", ".md"} or path.name == "requirements.txt"))
        if safe and allowed:
            included.append((source, Path(*relative.parts[1:]).as_posix()))
        else:
            excluded.append(source)
    return included, excluded


def submission_plan(root):
    """Keep the runnable code/ tree and both organizer report path conventions."""
    root=Path(root).resolve()
    plan=[("README.md","README.md")]
    for p in sorted((root/"code").rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel=p.relative_to(root)
        if any(part in EXCLUDED_PARTS or part.startswith(".env") for part in rel.parts):
            continue
        if p.suffix.lower() in {".py",".md",".ps1"} or p.name=="requirements.txt":
            plan.append((rel.as_posix(),rel.as_posix()))
    for name in ("evaluation_report.md","usage_report.md"):
        plan.append(("code/evaluation/"+name,"evaluation/"+name))
    return plan


def build_archive(root,output):
    root=Path(root).resolve();output=Path(output).resolve()
    plan=submission_plan(root)
    if len({target for _,target in plan})!=len(plan):
        raise ValueError("duplicate_archive_target")
    with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for source,target in plan:
            text=(root/source).read_text(encoding="utf-8")
            # Only local-location privacy redaction. Runtime statements are not
            # rewritten; generated reports retain metrics and input hashes.
            if Path(source).suffix==".md":
                for location,label in ((str(root),"<repository>"),(str(Path.home()),"<user-home>")):
                    for spelling in (location,location.replace("\\","/"),location.replace("\\","\\\\")):
                        text=text.replace(spelling,label)
            if re.search(r"sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----",text):
                raise ValueError("possible_secret_in_archive:"+source)
            info=zipfile.ZipInfo(target,date_time=(2026,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o100644<<16
            archive.writestr(info,text.encode("utf-8"))
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("zip_crc_failure")
    return {"members":len(plan),"bytes":output.stat().st_size,
            "sha256":hashlib.sha256(output.read_bytes()).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="List source -> archive paths and exclusions; write nothing")
    parser.add_argument("--build",action="store_true",help="Create root code.zip with runnable code tree, README and mandatory reports")
    args = parser.parse_args()
    if args.build and not args.dry_run:
        root=Path(__file__).resolve().parents[2]
        print(json.dumps(build_archive(root,root/"code.zip"),sort_keys=True,indent=2))
        return
    if not args.dry_run:
        parser.error("Only --dry-run is implemented; Phase 0 never creates a submission archive.")
    root = Path(__file__).resolve().parents[2]
    included, excluded = package_plan(root)
    print("DRY RUN ONLY: no archive created; final runnable pipeline and reports are pending.")
    for source, target in included:
        print(f"INCLUDE {source} -> {target}")
    print("EXCLUDE .git/")
    for source in excluded:
        print(f"EXCLUDE {source}")
    print("log.txt is a separate transcript upload; original dataset is external to the code archive.")


if __name__ == "__main__":
    main()
