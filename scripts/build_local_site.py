"""Build the complete local preview when Ruby/Jekyll is unavailable."""

from __future__ import annotations

import html
import json
import re
import shutil
from datetime import date, datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

import markdown
import yaml


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "_site"
SITE_URL = "https://171k.my"
SITE_DESCRIPTION = "Cybersecurity field notes, CTF writeups, tools, and practical learning by Razlan."
OG_IMAGE = f"{SITE_URL}/assets/video/pond-poster.jpg"


def split_document(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8-sig")
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.S)
    if not match:
        return {}, text
    return yaml.safe_load(match.group(1)) or {}, text[match.end():]


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower().strip())
    return value.strip("-") or "note"


def parsed_date(value: object, fallback: date) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if value:
        parts = [int(part) for part in str(value).split("-")]
        return date(parts[0], parts[1], parts[2])
    return fallback


def plain_text(markdown_text: str) -> str:
    plain = re.sub(r"```.*?```", "", markdown_text, flags=re.S)
    plain = re.sub(r"!\[[^]]*]\([^)]*\)", " ", plain)
    plain = re.sub(r"\{:\s*[^}]*\}", " ", plain)
    plain = re.sub(r"<[^>]+>|[#*_`>\[\]()]", " ", plain)
    return re.sub(r"\s+", " ", plain).strip()


def excerpt(markdown_text: str, limit: int = 150) -> str:
    plain = plain_text(markdown_text)
    return plain[:limit].rstrip() + ("..." if len(plain) > limit else "")


def load_pages() -> list[dict]:
    pages: list[dict] = []
    for kind, folder in (
        ("quacks", "_quacks"),
        ("ctf", "_ctf"),
        ("tools", "_tools"),
        ("books", "_books"),
        ("projects", "_projects"),
        ("certifications", "_certifications"),
        ("achievements", "_achievements"),
    ):
        for path in sorted((ROOT / folder).rglob("*.md")):
            meta, body = split_document(path)
            if meta.get("published") is False:
                continue
            title = str(meta.get("title") or path.stem)
            item_date = parsed_date(meta.get("date"), date.fromtimestamp(path.stat().st_mtime))
            if kind == "quacks":
                filename_title = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", path.stem)
                url = str(meta.get("permalink") or f"/quacks/{slug(filename_title)}/")
            elif kind == "ctf":
                url = str(meta.get("permalink") or f"/ctf/{slug(path.stem)}/")
            else:
                url = str(meta.get("permalink") or f"/{kind}/{slug(title)}/")
            pages.append({
                "kind": kind,
                "path": path,
                "meta": meta,
                "body": body,
                "title": title,
                "date": item_date,
                "url": url,
                "description": str(meta.get("description") or excerpt(body, 158) or SITE_DESCRIPTION),
            })
    return pages


def sidebar(pages: list[dict], current: str) -> str:
    quacks = sorted((p for p in pages if p["kind"] == "quacks"), key=lambda p: p["date"], reverse=True)
    tools = sorted((p for p in pages if p["kind"] == "tools"), key=lambda p: p["title"].lower())
    books = sorted((p for p in pages if p["kind"] == "books"), key=lambda p: p["title"].lower())
    events: dict[str, list[dict]] = {}
    for page in (p for p in pages if p["kind"] == "ctf"):
        events.setdefault(str(page["meta"].get("ctf_event") or "Other"), []).append(page)

    def link(page: dict) -> str:
        active = ' aria-current="page"' if page["url"] == current else ""
        return f'<li><a href="{page["url"]}"{active}>{html.escape(page["title"])}</a></li>'

    def dropdown(title: str, section_id: str, content: str, is_open: bool) -> str:
        expanded = "true" if is_open else "false"
        hidden = "" if is_open else " hidden"
        icon = "−" if is_open else "+"
        return f'''<div class="sidebar-section sidebar-section-collapsible"><button class="sidebar-section-toggle" type="button" onclick="toggleSidebarSection(this)" aria-expanded="{expanded}" aria-controls="{section_id}"><span class="sidebar-label">{title}</span><span class="sidebar-section-icon" aria-hidden="true">{icon}</span></button><div class="sidebar-section-body" id="{section_id}"{hidden}>{content}</div></div>'''

    event_html = []
    for event in sorted(events, reverse=True):
        event_id = "ctf-" + slug(event)
        links = "".join(f'<a href="{p["url"]}" class="challenge-link">{html.escape(p["title"])}</a>' for p in sorted(events[event], key=lambda p: p["title"]))
        event_html.append(f'<div class="ctf-group"><button class="ctf-group-header" type="button" onclick="toggleCtfGroup(\'{event_id}\', this)" aria-expanded="false" aria-controls="{event_id}"><span class="ctf-name">{html.escape(event)}</span><span class="ctf-toggle" aria-hidden="true">+</span></button><div class="challenge-list" id="{event_id}" hidden>{links}</div></div>')

    home_active = ' aria-current="page"' if current == "/" else ""
    pond_active = ' aria-current="page"' if current == "/pond/" else ""
    search_active = ' aria-current="page"' if current == "/search/" else ""
    all_quacks_active = ' aria-current="page"' if current == "/quacks/" else ""
    quack_links = f'<li><a href="/quacks/"{all_quacks_active}>All quacks</a></li>' + "".join(link(p) for p in quacks[:6])
    quacks_open = current == "/quacks/" or any(page["url"] == current for page in quacks)
    quacks_dropdown = dropdown("Quacks", "sidebar-quacks", f'<p class="sidebar-section-hint">Personal notes, event stories, and reflections.</p><ul class="sidebar-list compact-list">{quack_links}</ul>', quacks_open)
    ctf_dropdown = dropdown("CTF library", "sidebar-ctf-library", f'<p class="sidebar-section-hint">Challenges, solutions, and event writeups.</p><div class="ctf-navigation">{"".join(event_html)}</div>', current.startswith("/ctf/"))
    portfolio_dropdown = dropdown("Portfolio", "sidebar-portfolio", f'<ul class="sidebar-list"><li><a href="/projects/"{' aria-current="page"' if current.startswith('/projects/') else ''}>Projects</a></li><li><a href="/certifications/"{' aria-current="page"' if current.startswith('/certifications/') else ''}>Certifications</a></li><li><a href="/achievements/"{' aria-current="page"' if current.startswith('/achievements/') else ''}>Achievements</a></li></ul>', current.startswith(("/projects/", "/certifications/", "/achievements/")))
    tools_dropdown = dropdown("Toolkit", "sidebar-toolkit", f'<p class="sidebar-section-hint">Security tools and practical references.</p><ul class="sidebar-list">{"".join(link(p) for p in tools)}</ul>', current.startswith("/tools/"))
    books_dropdown = dropdown("Library", "sidebar-library", f'<p class="sidebar-section-hint">Cookbooks, sheets, and longer references.</p><ul class="sidebar-list">{"".join(link(p) for p in books)}</ul>', current.startswith("/books/"))
    return f'''<aside class="sidebar" aria-label="Site navigation"><nav class="sidebar-nav">
<div class="sidebar-section"><p class="sidebar-label">Start here</p><ul class="sidebar-list"><li><a href="/"{home_active}>Overview</a></li><li><a href="/#featured">Featured work</a></li><li><a href="/search/"{search_active}>Search</a></li><li><a href="/#contact">Contact</a></li></ul></div>
{quacks_dropdown}
{portfolio_dropdown}
{ctf_dropdown}
{tools_dropdown}{books_dropdown}<div class="sidebar-pond-cta"><a class="sidebar-pond-link" href="/pond/"{pond_active}><span class="sidebar-pond-copy"><small>Interactive</small><strong>Go to Duck Pond</strong></span><span class="sidebar-pond-arrow" aria-hidden="true">&#8599;</span></a></div>
</nav></aside><script>function toggleSidebarSection(button){{const target=document.getElementById(button.getAttribute('aria-controls'));if(!target)return;const open=target.hidden;document.querySelectorAll('.sidebar-section-toggle[aria-expanded="true"]').forEach(function(other){{if(other===button)return;const panel=document.getElementById(other.getAttribute('aria-controls'));if(panel)panel.hidden=true;other.setAttribute('aria-expanded','false');const otherIcon=other.querySelector('.sidebar-section-icon');if(otherIcon)otherIcon.textContent='+';}});target.hidden=!open;button.setAttribute('aria-expanded',open?'true':'false');const icon=button.querySelector('.sidebar-section-icon');if(icon)icon.textContent=open?'−':'+';}}function toggleCtfGroup(groupId,button){{const target=document.getElementById(groupId);if(!target)return;const open=target.hidden;target.hidden=!open;button.setAttribute('aria-expanded',open?'true':'false');const icon=button.querySelector('.ctf-toggle');if(icon)icon.textContent=open?'−':'+';}}</script>'''


def pdf_launch(source: str, title: str) -> str:
    if not source:
        return ""
    return f'''<button class="pdf-launch" type="button" data-pdf="{html.escape(source, quote=True)}" data-pdf-title="{html.escape(title, quote=True)}" aria-haspopup="dialog">Read PDF writeup</button>'''


def portfolio_links(meta: dict) -> str:
    links = []
    for field, label in (("repository", "Repository"), ("demo", "Live demo"), ("credential", "Verify credential"), ("link", "View reference")):
        if meta.get(field):
            links.append(f'<a href="{html.escape(str(meta[field]), quote=True)}" rel="noopener">{label}</a>')
    return f'<nav class="portfolio-links" aria-label="Related links">{"".join(links)}</nav>' if links else ""


def post_gallery(meta: dict) -> str:
    gallery = str(meta.get("gallery") or "").strip().strip("/")
    if not gallery:
        return ""
    folder = ROOT / gallery
    if not folder.is_dir():
        return ""
    images = sorted(path for path in folder.iterdir() if path.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".gif"} and path.stat().st_size)
    if not images:
        return ""
    title = str(meta.get("gallery_title") or "Gallery")
    alt = str(meta.get("gallery_alt") or meta.get("title") or "Post gallery image")
    figures = "".join(
        f'<figure><img src="/{gallery}/{html.escape(path.name, quote=True)}" alt="{html.escape(alt, quote=True)}, image {index} of {len(images)}" loading="lazy" decoding="async"></figure>'
        for index, path in enumerate(images, start=1)
    )
    return f'<section class="post-gallery" aria-labelledby="post-gallery-heading"><h2 id="post-gallery-heading">{html.escape(title)}</h2><div class="post-gallery-grid">{figures}</div></section>'


def shell(title: str, content: str, pages: list[dict], url: str, page_class: str, description: str, pdf_source: str = "", pond: bool = False) -> str:
    header = (ROOT / "_includes" / "header.html").read_text(encoding="utf-8")
    pdf_viewer = (ROOT / "_includes" / "pdf-viewer.html").read_text(encoding="utf-8") if pdf_source else ""
    pdf_button = pdf_launch(pdf_source, title.removesuffix(" | 171k"))
    scripts = (ROOT / "_includes" / "scripts.html").read_text(encoding="utf-8")
    audio_player = (ROOT / "_includes" / "audio-player.html").read_text(encoding="utf-8")
    canonical = SITE_URL + url
    page_type = "website" if url == "/" else "article"
    video = ""
    if url == "/":
        video = '<video id="pond-video" muted loop playsinline preload="none" poster="/assets/video/pond-poster.jpg"><source data-src="/assets/video/pond.mp4" type="video/mp4"></video>'
    pond_head = '''<link rel="stylesheet" href="/assets/css/pond-experience.css?v=6"><script type="importmap">{"imports":{"three":"https://cdn.jsdelivr.net/npm/three@0.185.1/build/three.module.js","three/addons/":"https://cdn.jsdelivr.net/npm/three@0.185.1/examples/jsm/"}}</script>''' if pond else ""
    pond_scripts = '<script src="/assets/js/pond-fallback.js?v=4"></script><script type="module" src="/assets/js/pond-experience.js?v=11"></script>' if pond else ""
    return f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta id="theme-color" name="theme-color" content="#07171e"><title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description, quote=True)}"><link rel="canonical" href="{canonical}"><meta property="og:site_name" content="171k"><meta property="og:title" content="{html.escape(title, quote=True)}"><meta property="og:description" content="{html.escape(description, quote=True)}"><meta property="og:url" content="{canonical}"><meta property="og:type" content="{page_type}"><meta property="og:image" content="{OG_IMAGE}"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{html.escape(title, quote=True)}"><meta name="twitter:description" content="{html.escape(description, quote=True)}"><meta name="twitter:image" content="{OG_IMAGE}"><link rel="alternate" type="application/atom+xml" title="171k feed" href="{SITE_URL}/feed.xml">
<script>(function(){{let stored=null;try{{stored=localStorage.getItem('theme')}}catch(error){{}}const theme=stored==='light'||stored==='dark'?stored:'dark';document.documentElement.dataset.theme=theme;document.documentElement.style.colorScheme=theme;document.getElementById('theme-color').content=theme==='light'?'#e7f0e9':'#07171e'}}());</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.7.2/css/all.min.css"><link rel="stylesheet" href="/assets/css/styles.css?v=9"><link rel="stylesheet" href="/assets/css/pond-theme.css?v=21">{pond_head}<link rel="icon" type="image/png" href="/assets/images/brand/favicon.png"></head>
<body class="{page_class}"><div class="pond-wallpaper" aria-hidden="true">{video}<div class="pond-tint"></div></div><a class="skip-link" href="#main-content">Skip to the writing</a>{header}{sidebar(pages, url)}<main class="main-content" id="main-content">{content}{pdf_button}</main>{pdf_viewer}{audio_player}{scripts}{pond_scripts}</body></html>'''


def homepage(pages: list[dict]) -> str:
    featured_projects = sorted(
        (p for p in pages if p["kind"] == "projects" and p["meta"].get("featured") is True),
        key=lambda p: p["date"],
        reverse=True,
    )
    featured_other = sorted(
        (p for p in pages if p["kind"] in {"quacks", "certifications", "achievements"} and p["meta"].get("featured") is True),
        key=lambda p: p["date"],
        reverse=True,
    )
    featured = (featured_projects + featured_other)[:6]
    labels = {"projects": "Project", "certifications": "Certification", "achievements": "Achievement"}
    rows = []
    for item in featured:
        category = labels.get(item["kind"], str((item["meta"].get("categories") or ["Field note"])[0]))
        summary = item["description"]
        technologies = item["meta"].get("technologies") or []
        tech_html = ""
        if item["kind"] == "projects" and technologies:
            tech_html = '<div class="post-row-tech" aria-label="Technologies used">' + "".join(f'<span>{html.escape(str(technology))}</span>' for technology in technologies[:4]) + "</div>"
        rows.append(f'''<article class="post-row"><a href="{item["url"]}" class="post-row-link" aria-label="Read {html.escape(item["title"])}"></a><div class="post-row-meta"><time datetime="{item["date"].isoformat()}">{item["date"]:%d %b %Y}</time><span>{html.escape(category)}</span></div><div class="post-row-body"><h3>{html.escape(item["title"])}</h3><p>{html.escape(summary)}</p>{tech_html}</div><span class="post-row-arrow" aria-hidden="true">↗</span></article>''')
    if not rows:
        rows.append('<div class="portfolio-empty"><p>Mark an entry with <code>featured: true</code> to pin it here.</p></div>')
    return f'''<section class="profile-panel" id="title"><p class="profile-kicker">Hello from the pond. I'm</p><h1>Razlan <span>/ 171k</span></h1><p class="profile-role">Cybersecurity student building CTF challenges, forensic tools, and interactive security experiences.</p><div class="profile-copy"><p>I design security challenges, investigate digital evidence, build practical tooling, and document the mistakes and discoveries along the way. <strong>171k</strong> comes from “itik”, Malay for duck.</p></div><dl class="profile-facts"><div><dt>17 challenges</dt><dd>Authored for the OPUCC26 CTF</dd></div><div><dt>48 teams</dt><dd>Supported during a 24-hour competition</dd></div><div><dt>President</dt><dd>UiTM Cyberheroes Club, 2025/2026</dd></div></dl><nav class="profile-actions" aria-label="Primary actions"><a class="profile-action-primary" href="/projects/">View projects</a><a href="/search/?q=ctf">Read CTF writeups</a><a href="mailto:lanbuatkeje@gmail.com">Contact me</a></nav><a class="profile-pond-entry" href="/pond/"><span><small>Interactive portfolio</small><strong>Go to Duck Pond</strong><span>Explore projects, writeups, and achievements through the 3D pond.</span></span><b aria-hidden="true">↗</b></a><div class="profile-socials" id="contact"><span>Elsewhere</span><a href="https://www.linkedin.com/in/razlan-ramli-99a527186/">LinkedIn ↗</a><a href="https://discord.com/users/871586020381061160">Discord ↗</a><a href="mailto:lanbuatkeje@gmail.com">Email ↗</a></div></section>
<section class="recent-section" id="featured"><div class="section-heading"><div><p class="section-kicker">Pinned highlights</p><h2>Featured work</h2></div><span class="section-count">{len(featured)} pinned</span></div><div class="post-list">{"".join(rows)}</div></section>
<section class="collection-grid" aria-label="Explore the site"><div class="collection-card"><span class="collection-index">01</span><h2>CTF writeups</h2><p>Challenge notes grouped by event, ready from the sidebar.</p></div><div class="collection-card"><span class="collection-index">02</span><h2>Tools I use</h2><p>Practical references for Wireshark, Apktool, and the rest of the toolkit.</p></div><div class="collection-card"><span class="collection-index">03</span><h2>Books &amp; sheets</h2><p>Longer notes, cookbooks, and reusable learning material.</p></div></section>'''


def quacks_index(pages: list[dict]) -> str:
    quacks = sorted((p for p in pages if p["kind"] == "quacks"), key=lambda p: p["date"], reverse=True)
    rows = []
    for quack in quacks:
        category = str((quack["meta"].get("categories") or ["Quack"])[0])
        rows.append(f'''<article class="post-row"><a href="{quack["url"]}" class="post-row-link" aria-label="Read {html.escape(quack["title"])}"></a><div class="post-row-meta"><time datetime="{quack["date"].isoformat()}">{quack["date"]:%d %b %Y}</time><span>{html.escape(category)}</span></div><div class="post-row-body"><h3>{html.escape(quack["title"])}</h3><p>{html.escape(quack["description"])}</p></div><span class="post-row-arrow" aria-hidden="true">↗</span></article>''')
    listing = "".join(rows) if rows else '<div class="portfolio-empty"><p>Your quacks will appear here.</p></div>'
    return f'''<section class="portfolio-page"><p class="section-kicker">From the notebook</p><h1>Quacks</h1><p class="portfolio-intro">Blog-style notes, event stories, reflections, and things I wanted to write down.</p><div class="post-list">{listing}</div></section>'''


def portfolio_index(kind: str, pages: list[dict]) -> str:
    settings = {
        "projects": ("Proof of work", "Projects", "Things I have built, investigated, automated, or learned by doing.", "Projects will appear here when they are ready."),
        "certifications": ("Validated learning", "Certifications", "Certifications, formal training, and courses I have completed.", "Certifications will appear here when they are added."),
        "achievements": ("Milestones", "Achievements", "CTF placements, awards, recognition, and moments worth remembering.", "Achievements will appear here when they are added."),
    }
    kicker, title, intro, empty = settings[kind]
    entries = sorted((p for p in pages if p["kind"] == kind), key=lambda p: p["date"], reverse=True)
    rows = []
    for item in entries:
        meta_label = item["meta"].get("status") or item["meta"].get("issuer") or item["meta"].get("organization") or ""
        technologies = item["meta"].get("technologies") or []
        tags = f'<p class="portfolio-tags">{html.escape(" / ".join(map(str, technologies)))}</p>' if technologies else ""
        label = f'<span>{html.escape(str(meta_label))}</span>' if meta_label else ""
        summary = str(item["meta"].get("description") or item["meta"].get("summary") or item["description"])
        rows.append(f'''<article class="portfolio-entry"><div class="portfolio-entry-meta"><time datetime="{item["date"].isoformat()}">{item["date"]:%Y}</time>{label}</div><div><h2><a href="{item["url"]}">{html.escape(item["title"])}</a></h2><p>{html.escape(summary)}</p>{tags}</div></article>''')
    listing = f'<div class="portfolio-list">{"".join(rows)}</div>' if rows else f'<div class="portfolio-empty"><p>{empty}</p></div>'
    return f'''<section class="portfolio-page"><p class="section-kicker">{kicker}</p><h1>{title}</h1><p class="portfolio-intro">{intro}</p>{listing}</section>'''


def pond_page(pages: list[dict]) -> str:
    experience = (ROOT / "_includes" / "pond-experience.html").read_text(encoding="utf-8")
    posts = []
    for page in pages:
        categories = page["meta"].get("categories") or []
        if isinstance(categories, str):
            categories = [categories]
        posts.append({
            "id": page["url"],
            "title": page["title"],
            "url": page["url"],
            "description": page["description"],
            "date": page["date"].isoformat(),
            "collection": page["kind"],
            "categories": list(map(str, categories)),
            "ctfEvent": str(page["meta"].get("ctf_event") or ""),
            "ctfCategory": str(page["meta"].get("ctf_category") or ""),
            "featured": page["meta"].get("featured") is True,
            "pond": page["meta"].get("pond") is True,
        })
    data = json.dumps(posts, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    return f'{experience}<script id="pond-post-data" type="application/json">{data}</script>'


def search_page(pages: list[dict]) -> str:
    index = [{"title": p["title"], "url": p["url"], "excerpt": p["description"][:220], "type": p["kind"]} for p in pages]
    data = json.dumps(index, ensure_ascii=False).replace("<", "\\u003c").replace("&", "\\u0026")
    return f'''<section class="search-page"><p class="section-kicker">Search the pond</p><h1>Find a note</h1><form class="search-page-form" action="/search/" method="get" role="search"><label for="site-search">Search notes, writeups, portfolio entries, tools, and books</label><div><input id="site-search" type="search" name="q" autocomplete="off" placeholder="Try forensics, Wireshark, or phishing"><button type="submit">Search</button></div></form><p id="search-summary" class="search-summary" aria-live="polite">Enter a term to search the pond.</p><div id="search-results" class="search-results"></div></section><script id="search-index" type="application/json">{data}</script>
<script>(function(){{const form=document.querySelector('.search-page-form'),input=document.getElementById('site-search'),summary=document.getElementById('search-summary'),results=document.getElementById('search-results'),index=JSON.parse(document.getElementById('search-index').textContent);function render(query){{const normalized=query.trim().toLowerCase();results.replaceChildren();input.value=query;if(!normalized){{summary.textContent='Enter a term to search the pond.';return;}}const matches=index.filter(item=>(item.title+' '+item.excerpt+' '+item.type).toLowerCase().includes(normalized)).slice(0,30);summary.textContent=matches.length+(matches.length===1?' result':' results')+' for “'+query+'”.';matches.forEach(function(item){{const article=document.createElement('article'),link=document.createElement('a'),type=document.createElement('span'),title=document.createElement('h2'),copy=document.createElement('p');article.className='search-result';link.href=item.url;type.textContent=item.type;title.textContent=item.title;copy.textContent=item.excerpt;link.append(type,title,copy);article.append(link);results.append(article);}});}}form.addEventListener('submit',function(event){{event.preventDefault();const query=input.value;history.replaceState(null,'','/search/?q='+encodeURIComponent(query));render(query);}});render(new URLSearchParams(location.search).get('q')||'');}}());</script>'''


def write_route(url: str, content: str) -> None:
    if url == "/":
        target = OUT / "index.html"
    elif Path(url).suffix:
        target = OUT / url.strip("/")
    else:
        target = OUT / url.strip("/") / "index.html"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def not_found_page() -> str:
    return '''<section class="not-found" aria-labelledby="not-found-title"><p class="section-kicker">404 · Lost in the reeds</p><h1 id="not-found-title">This page swam away.</h1><p>The link may be outdated, or the note may have moved somewhere else in the pond.</p><nav class="not-found-actions" aria-label="Page recovery options"><a class="not-found-primary" href="/">Return home</a><a href="/search/">Search the notebook</a><a href="/pond/">Visit Duck Pond</a></nav></section>'''


def write_discovery_files(pages: list[dict]) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    quacks = sorted((p for p in pages if p["kind"] == "quacks"), key=lambda p: p["date"], reverse=True)
    entries = "".join(f'<entry><title>{xml_escape(p["title"])}</title><link href="{SITE_URL}{p["url"]}"/><id>{SITE_URL}{p["url"]}</id><published>{p["date"].isoformat()}T00:00:00Z</published><updated>{p["date"].isoformat()}T00:00:00Z</updated><summary>{xml_escape(p["description"])}</summary></entry>' for p in quacks[:20])
    feed = f'<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>171k</title><subtitle>{xml_escape(SITE_DESCRIPTION)}</subtitle><link href="{SITE_URL}/feed.xml" rel="self"/><link href="{SITE_URL}/"/><id>{SITE_URL}/</id><updated>{now}</updated><author><name>Razlan</name></author>{entries}</feed>'
    urls = ["/", "/pond/", "/search/", "/quacks/", "/projects/", "/certifications/", "/achievements/"] + [p["url"] for p in pages]
    sitemap = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(f'<url><loc>{SITE_URL}{url}</loc></url>' for url in urls) + '</urlset>'
    (OUT / "feed.xml").write_text(feed, encoding="utf-8")
    (OUT / "sitemap.xml").write_text(sitemap, encoding="utf-8")
    (OUT / "robots.txt").write_text(f"User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}/sitemap.xml\n", encoding="utf-8")


def main() -> None:
    pages = load_pages()
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    shutil.copytree(ROOT / "assets", OUT / "assets")
    shutil.copy2(ROOT / "CNAME", OUT / "CNAME")
    write_route("/", shell("171k | Razlan's duck pond", homepage(pages), pages, "/", "home-page", SITE_DESCRIPTION))
    write_route("/pond/", shell("Duck Pond | 171k", pond_page(pages), pages, "/pond/", "pond-page", "Explore Razlan's cybersecurity notebook by guiding a white duck through an interactive 3D pond.", pond=True))
    write_route("/search/", shell("Search | 171k", search_page(pages), pages, "/search/", "article-page", "Search Razlan's cybersecurity notes, CTF writeups, portfolio entries, tools, and books."))
    write_route("/quacks/", shell("Quacks | 171k", quacks_index(pages), pages, "/quacks/", "article-page", "Blog-style field notes, experiences, reflections, and cybersecurity stories by Razlan."))
    write_route("/projects/", shell("Projects | 171k", portfolio_index("projects", pages), pages, "/projects/", "article-page", "Cybersecurity projects, labs, scripts, and practical experiments by Razlan."))
    write_route("/certifications/", shell("Certifications | 171k", portfolio_index("certifications", pages), pages, "/certifications/", "article-page", "Professional certifications and completed cybersecurity training by Razlan."))
    write_route("/achievements/", shell("Achievements | 171k", portfolio_index("achievements", pages), pages, "/achievements/", "article-page", "CTF placements, awards, and cybersecurity milestones achieved by Razlan."))
    write_route("/404.html", shell("Page not found | 171k", not_found_page(), pages, "/404.html", "article-page not-found-page", "This page drifted away from Razlan's cybersecurity pond."))
    for page in pages:
        rendered = markdown.markdown(page["body"], extensions=["extra", "sane_lists"])
        rendered += post_gallery(page["meta"])
        rendered += portfolio_links(page["meta"])
        write_route(page["url"], shell(f'{page["title"]} | 171k', rendered, pages, page["url"], "article-page", page["description"], str(page["meta"].get("pdf") or "")))
    write_discovery_files(pages)
    print(f"Built {len(pages) + 8} pages into {OUT}")


if __name__ == "__main__":
    main()
