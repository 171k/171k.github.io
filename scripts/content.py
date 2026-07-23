"""Create and validate Markdown content for the 171k blog."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTENT_FOLDERS = {
    "quack": ROOT / "_quacks",
    "ctf": ROOT / "_ctf",
    "tool": ROOT / "_tools",
    "book": ROOT / "_books",
    "project": ROOT / "_projects",
    "certification": ROOT / "_certifications",
    "achievement": ROOT / "_achievements",
}


def slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower().strip()).strip("-")
    return cleaned or "untitled"


def parse_date(value: str) -> str:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date().isoformat()
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use a date in YYYY-MM-DD format.") from error


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def list_value(value: str) -> str:
    items = [item.strip() for item in value.split(",") if item.strip()]
    return "[" + ", ".join(quoted(item) for item in items) + "]"


def normalize_pdf(value: str) -> str:
    path = value.strip().replace("\\", "/")
    if "/" not in path:
        path = f"/assets/pdfs/{path}"
    elif not path.startswith("/"):
        path = "/" + path
    return path


def new_content(args: argparse.Namespace) -> int:
    published = args.date
    title_slug = slug(args.title)
    description = args.description or args.summary
    if not description:
        print(f"{args.kind.title()} content needs --description for cards and previews.", file=sys.stderr)
        return 2

    if args.kind == "quack":
        target = CONTENT_FOLDERS[args.kind] / f"{published}-{title_slug}.md"
        categories = args.category or "Field Note"
    elif args.kind == "ctf":
        if not args.event or not args.category:
            print("CTF content needs both --event and --category.", file=sys.stderr)
            return 2
        target = CONTENT_FOLDERS[args.kind] / slug(args.event) / slug(args.category) / f"{title_slug}.md"
        categories = f"{args.category}, Writeup"
    else:
        target = CONTENT_FOLDERS[args.kind] / f"{title_slug}.md"
        categories = args.category or args.kind.title()

    if target.exists():
        print(f"Already exists: {target.relative_to(ROOT)}", file=sys.stderr)
        return 1

    front_matter = [
        "---",
        f"title: {quoted(args.title)}",
        f"date: {published}",
        f"categories: {list_value(categories)}",
        f"tags: {list_value(args.tags)}",
    ]
    if description:
        front_matter.append(f"description: {quoted(description)}")
    if args.kind == "quack":
        front_matter.append(f"permalink: /quacks/{title_slug}/")
    if args.kind == "ctf":
        front_matter.extend([
            f"ctf_event: {quoted(args.event)}",
            f"ctf_category: {quoted(args.category)}",
        ])
    if args.kind == "project":
        front_matter.extend([
            f"status: {quoted(args.status or 'In progress')}",
            f"technologies: {list_value(args.technologies)}",
        ])
        if args.repository:
            front_matter.append(f"repository: {quoted(args.repository)}")
        if args.demo:
            front_matter.append(f"demo: {quoted(args.demo)}")
    elif args.kind == "certification":
        if not args.issuer:
            print("Certification content needs --issuer.", file=sys.stderr)
            return 2
        front_matter.append(f"issuer: {quoted(args.issuer)}")
        if args.credential:
            front_matter.append(f"credential: {quoted(args.credential)}")
    elif args.kind == "achievement":
        if not args.organization:
            print("Achievement content needs --organization.", file=sys.stderr)
            return 2
        front_matter.append(f"organization: {quoted(args.organization)}")
        if args.link:
            front_matter.append(f"link: {quoted(args.link)}")
    front_matter.append(f"pond: {'true' if args.pond else 'false'}")
    front_matter.append(f"featured: {'true' if args.featured else 'false'}")
    if args.pdf:
        front_matter.append(f"pdf: {quoted(normalize_pdf(args.pdf))}")
    front_matter.extend(["---", "", f"# {args.title}", "", "Start writing here.", ""])

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(front_matter), encoding="utf-8")
    print(f"Created {target.relative_to(ROOT)}")
    return 0


def split_document(path: Path) -> tuple[dict, str, str]:
    text = path.read_text(encoding="utf-8-sig")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.S)
    if not match:
        return {}, text, ""
    return yaml.safe_load(match.group(1)) or {}, text[match.end():], match.group(1)


def local_asset_paths(text: str) -> set[str]:
    candidates = re.findall(r"(?:src|href|data-pdf)=[\"'](/assets/[^\"']+)", text)
    candidates += re.findall(r"!?\[[^]]*\]\((/assets/[^)\s]+)", text)
    return {candidate.split("#", 1)[0].split("?", 1)[0] for candidate in candidates}


def validate() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    checked = 0
    pond_entries: dict[str, list[str]] = {kind: [] for kind in CONTENT_FOLDERS}

    for kind, folder in CONTENT_FOLDERS.items():
        for path in sorted(folder.rglob("*.md")):
            checked += 1
            relative = path.relative_to(ROOT).as_posix()
            meta, body, raw_meta = split_document(path)
            if not raw_meta:
                errors.append(f"{relative}: missing front matter")
                continue
            if not str(meta.get("title") or "").strip():
                errors.append(f"{relative}: missing title")
            if not str(meta.get("description") or "").strip():
                errors.append(f"{relative}: missing description used by cards")
            if "pond" not in meta or not isinstance(meta.get("pond"), bool):
                errors.append(f"{relative}: pond must be true or false")
            elif meta["pond"]:
                pond_entries[kind].append(relative)

            raw_date = re.search(r"^date:\s*['\"]?([^'\"\s]+)", raw_meta, re.M)
            date_text = raw_date.group(1) if raw_date else ""
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_text):
                errors.append(f"{relative}: date must use YYYY-MM-DD")
            else:
                try:
                    date.fromisoformat(date_text)
                except ValueError:
                    errors.append(f"{relative}: invalid calendar date {date_text}")

            if kind == "quack" and date_text and not path.name.startswith(f"{date_text}-"):
                errors.append(f"{relative}: filename date must match front matter date {date_text}")
            if kind == "ctf":
                if not meta.get("ctf_event"):
                    errors.append(f"{relative}: missing ctf_event")
                if not meta.get("ctf_category"):
                    errors.append(f"{relative}: missing ctf_category")
            elif kind == "certification" and not meta.get("issuer"):
                errors.append(f"{relative}: missing issuer")
            elif kind == "achievement" and not meta.get("organization"):
                errors.append(f"{relative}: missing organization")

            pdf = str(meta.get("pdf") or "")
            if pdf:
                if not pdf.startswith("/assets/pdfs/"):
                    errors.append(f"{relative}: pdf must be inside /assets/pdfs/")
                elif not (ROOT / pdf.lstrip("/")).is_file():
                    errors.append(f"{relative}: PDF not found at {pdf}")
            if "pdf_viewer" in meta or 'class="pdf-launch"' in body:
                errors.append(f"{relative}: use the pdf field instead of viewer HTML")

            for asset in sorted(local_asset_paths(body)):
                if not (ROOT / asset.lstrip("/")).exists():
                    errors.append(f"{relative}: asset not found at {asset}")

    for kind, selected in pond_entries.items():
        if len(selected) > 3:
            errors.append(f"{kind}: {len(selected)} entries use pond: true; maximum is 3 per collection")

    page_files = [ROOT / "index.md", *sorted((ROOT / "_pages").rglob("*.md"))]
    for path in page_files:
        checked += 1
        relative = path.relative_to(ROOT).as_posix()
        meta, _, raw_meta = split_document(path)
        if not raw_meta:
            errors.append(f"{relative}: missing front matter")
            continue
        if not str(meta.get("title") or "").strip():
            errors.append(f"{relative}: missing title")
        if not str(meta.get("description") or "").strip():
            errors.append(f"{relative}: missing description used by page previews")

    stray_markdown = sorted((ROOT / "assets").rglob("*.md"))
    for path in stray_markdown:
        warnings.append(f"{path.relative_to(ROOT).as_posix()}: Markdown stored inside assets")

    for message in errors:
        print(f"ERROR: {message}")
    for message in warnings:
        print(f"WARNING: {message}")
    print(f"Checked {checked} content files: {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


def parser() -> argparse.ArgumentParser:
    main = argparse.ArgumentParser(description="Create and validate blog content.")
    commands = main.add_subparsers(dest="command", required=True)

    create = commands.add_parser("new", help="Create a new Markdown file")
    create.add_argument("kind", choices=CONTENT_FOLDERS)
    create.add_argument("title")
    create.add_argument("--date", type=parse_date, default=date.today().isoformat())
    create.add_argument("--event", help="CTF event name")
    create.add_argument("--category", help="Primary category")
    create.add_argument("--tags", default="", help="Comma-separated tags")
    create.add_argument("--pdf", help="PDF filename or /assets/pdfs/ path")
    create.add_argument("--description", help="Short description used by cards and search results")
    create.add_argument("--summary", help="Legacy alias for --description")
    create.add_argument("--featured", action="store_true", help="Show on the homepage")
    create.add_argument("--pond", action="store_true", help="Show in this collection's Duck Pond area")
    create.add_argument("--status", help="Project status")
    create.add_argument("--technologies", default="", help="Comma-separated project technologies")
    create.add_argument("--repository", help="Project repository URL")
    create.add_argument("--demo", help="Project demo URL")
    create.add_argument("--issuer", help="Certification issuer")
    create.add_argument("--credential", help="Credential verification URL")
    create.add_argument("--organization", help="Achievement organization")
    create.add_argument("--link", help="Achievement reference URL")

    commands.add_parser("check", help="Validate all Markdown content")
    return main


def main() -> int:
    args = parser().parse_args()
    return new_content(args) if args.command == "new" else validate()


if __name__ == "__main__":
    raise SystemExit(main())
