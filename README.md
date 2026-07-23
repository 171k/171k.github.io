# Managing the 171k blog

The easiest method is the content helper. Run commands from this folder.

## Create content

Create a normal quack:

```powershell
python scripts/content.py new quack "My quack title" --description "A short summary shown on cards." --category "Blue Team" --tags "forensics, windows"
```

Create a CTF writeup:

```powershell
python scripts/content.py new ctf "Challenge title" --description "A concise overview of the challenge and solution." --event "WGMY 2026" --category "Forensic" --tags "ctf, forensics"
```

Create a PDF writeup:

1. Put the PDF inside `assets/pdfs`.
2. Create the writeup with its PDF filename:

```powershell
python scripts/content.py new ctf "WGMY 2026 Writeup" --description "A PDF writeup covering the WGMY 2026 Misc challenges." --event "WGMY 2026" --category "Misc" --pdf "WGMY_2026.pdf"
```

The helper creates the Markdown file in the correct folder. Open that file and replace `Start writing here.` with your content. PDF buttons and the viewer are automatic.

Create a tool or book note:

```powershell
python scripts/content.py new tool "Tool name" --description "A practical reference for using this tool." --tags "forensics"
python scripts/content.py new book "Book title" --description "A concise overview of this book or reference note." --tags "reference"
```

Create a project:

```powershell
python scripts/content.py new project "Mobile Analysis Lab" --status "Completed" --technologies "Python, Frida, Android" --description "A repeatable lab for inspecting Android applications." --repository "https://github.com/username/repository" --featured
```

Create a certification:

```powershell
python scripts/content.py new certification "Certification name" --description "The skills covered by this certification." --issuer "Issuing organization" --credential "https://example.com/verify"
```

Create an achievement:

```powershell
python scripts/content.py new achievement "Top 10 at Example CTF" --organization "Example CTF" --description "Placed in the top 10 among participating teams." --link "https://example.com/results"
```

Use `--featured` for any quack, project, certification, or achievement you want to pin in the homepage Featured posts section. The homepage shows up to six featured entries, sorted by date. Everything still appears on its dedicated page.

Use `--pond` when creating an entry to place it in that collection's Duck Pond area. You can also set `pond: true` or `pond: false` directly in any content file. Each collection can have at most three entries marked `pond: true`; the content checker reports an error if the limit is exceeded.

Complete copyable examples are also available at:

- `_projects/EXAMPLE.md`
- `_certifications/EXAMPLE.md`
- `_achievements/EXAMPLE.md`

These examples are visible on the website so you can see the completed card and detail-page layouts. Copy an example, give the new file a descriptive name, and replace its contents. Delete the example file whenever you no longer need it.

## Add images

Put Quack images inside `assets/images/quacks/<quack-name>/`. Put CTF images inside `assets/images/ctf/<event-name>/`. Then use ordinary Markdown:

```md
![Useful description](/assets/images/quacks/my-quack/screenshot.webp)
```

You do not need to write HTML for images or PDFs.

## Duck Pond

The interactive pond is available at `/pond/`.

- It reads the existing Markdown collections automatically.
- It shows only entries marked `pond: true`, with a maximum of three from each collection.
- Each collection has its own area in the pond.
- Changing `pond` to `true` or `false` updates the available leaves on the next build.
- Three.js and its FBX loader are requested only on the pond page.

Desktop controls use WASD or the arrow keys to move, E to read a nearby leaf, and Escape to close the reader. Mobile visitors receive directional buttons and a separate Read button. The page includes a normal post-list fallback when WebGL or the 3D code is unavailable.

## Check and preview

Check metadata and asset paths:

```powershell
python scripts/content.py check
```

Build the local preview:

```powershell
python scripts/build_local_site.py
```

Start the local server if it is not already running:

```powershell
python -m http.server 4173 --directory _site
```

Then open `http://127.0.0.1:4173/`.

## Metadata rules

- Dates always use `YYYY-MM-DD`.
- Every published content entry requires a concise `description` for cards, previews, and search results.
- Post filenames begin with the same date as their metadata.
- CTF files require `ctf_event` and `ctf_category`.
- PDFs use one `pdf:` field and live inside `assets/pdfs`.
- Certifications require `issuer`.
- Achievements require `organization`.
- Categories and tags use lists such as `["Forensic", "Writeup"]`.

Copyable manual templates are available in `authoring/templates` if you do not want to use the helper.

## Project structure

```text
_quacks/          Blog-style posts
_ctf/             CTF writeups
_projects/        Project entries
_certifications/  Certification entries
_achievements/    Achievement entries
_tools/           Tool notes
_books/           Book and reference notes
_pages/           Archive, search, feed, and sitemap pages
_includes/        Shared site components
_layouts/         Shared page layouts
assets/           CSS, images, PDFs, video, and cursors
authoring/        Templates, drafts, and archived source notes
scripts/          Content, build, and optimization helpers
_site/            Generated local preview, hidden in VS Code
```

The files in `_site` are generated. Edit the Markdown collections, `_pages`, site components, or assets instead.
