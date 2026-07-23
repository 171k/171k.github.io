"""Create smaller WebP variants for large article screenshots."""

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ("authoring/source-images/curtin-2025/spideyvid.png", "assets/images/ctf/curtin-2025/spideyvid.webp"),
    ("authoring/source-images/curtin-2025/recognizexxd.png", "assets/images/ctf/curtin-2025/recognizexxd.webp"),
    ("authoring/source-images/tng-madani/phishingsite.png", "assets/images/quacks/tng-madani/phishingsite.webp"),
    ("authoring/source-images/taming-2025/techcorp.png", "assets/images/ctf/taming-2025/techcorp.webp"),
]


for source_name, target_name in TARGETS:
    source = ROOT / source_name
    target = ROOT / target_name
    target.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(source) as image:
        image.save(target, "WEBP", quality=88, method=6)
    before = source.stat().st_size
    after = target.stat().st_size
    print(f"{source_name} -> {target_name}: {before / 1024:.1f} KB -> {after / 1024:.1f} KB")
