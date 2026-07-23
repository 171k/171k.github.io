"""Validate generated pages and assets before deployment."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "_site"
SKIP_SCHEMES = ("mailto:", "tel:", "data:", "javascript:")


def route_target(path: str) -> Path:
    clean = unquote(path).lstrip("/")
    target = SITE / clean
    if path.endswith("/") or not target.suffix:
        target /= "index.html"
    return target


def main() -> int:
    issues: list[str] = []
    html_files = sorted(SITE.rglob("*.html"))

    for page in html_files:
        relative = page.relative_to(SITE).as_posix()
        soup = BeautifulSoup(page.read_text(encoding="utf-8"), "html.parser")

        for selector, label in (
            ("title", "title"),
            ('meta[name="description"]', "description"),
            ('link[rel="canonical"]', "canonical URL"),
        ):
            if not soup.select_one(selector):
                issues.append(f"{relative}: missing {label}")

        canonical = soup.select_one('link[rel="canonical"]')
        if canonical and not str(canonical.get("href", "")).startswith("https://171k.my/"):
            issues.append(f"{relative}: canonical URL does not use https://171k.my")

        headings = soup.find_all("h1")
        if len(headings) != 1:
            issues.append(f"{relative}: expected 1 h1, found {len(headings)}")

        ids = [node.get("id") for node in soup.select("[id]")]
        duplicates = sorted({value for value in ids if value and ids.count(value) > 1})
        if duplicates:
            issues.append(f"{relative}: duplicate ids {', '.join(duplicates)}")

        for node, attribute in ((item, "href") for item in soup.select("[href]")):
            value = str(node.get(attribute, "")).strip()
            if not value:
                issues.append(f"{relative}: empty href")
                continue
            if value.startswith(("#", "http://", "https://", *SKIP_SCHEMES)):
                continue
            path = urlsplit(value).path
            if path and not route_target(path).exists():
                issues.append(f"{relative}: missing internal target {value}")

        for node in soup.select("[src]"):
            value = str(node.get("src", "")).strip()
            if not value or value.startswith(("http://", "https://", *SKIP_SCHEMES)):
                continue
            path = urlsplit(value).path
            if path and not route_target(path).exists():
                issues.append(f"{relative}: missing asset {value}")

        for image in soup.find_all("img"):
            if image.get("alt") is None:
                issues.append(f"{relative}: image missing alt text")

        if re.search(r"\{:\s*[^}]+\}", str(soup)):
            issues.append(f"{relative}: raw Kramdown attribute syntax")

    for required in ("CNAME", "robots.txt", "sitemap.xml", "feed.xml"):
        if not (SITE / required).is_file():
            issues.append(f"missing generated {required}")

    if issues:
        print("Deployment check failed:")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print(f"Deployment check passed: {len(html_files)} HTML files validated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
