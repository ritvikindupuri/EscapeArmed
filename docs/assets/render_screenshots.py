"""Render terminal-style PNGs from the saved demo output in examples/.

Text is taken verbatim from the files. Line ranges select the important parts,
and an elision marker (...) shows where lines were skipped."""

import os
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "docs", "assets", "screenshots")
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 18)
BOLD = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 18)
UI = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16)
BG, FG, DIM = (13, 17, 23), (201, 209, 217), (110, 118, 129)
COLORS = {"PROVEN": (255, 123, 114), "CRITICAL": (255, 123, 114), "LIKELY": (227, 179, 65),
          "HIGH": (255, 166, 87), "MEDIUM": (227, 179, 65), "BLOCKED": (63, 185, 80),
          "ALLOWED": (63, 185, 80), "LOW": (121, 192, 255), "NA": DIM, "INFO": DIM,
          "Verdict: ESCAPABLE": (255, 123, 114), "Verdict: NO ESCAPE PATH PROVEN": (63, 185, 80)}
WRAP = 118
ELIDE = "\0..."


def select(path, ranges):
    lines = open(os.path.join(ROOT, path)).read().splitlines()
    out = []
    for i, (a, b) in enumerate(ranges):
        if i:
            out.append(ELIDE)
        out.extend(lines[a - 1:b])
    return out


def wrap(lines):
    res = []
    for line in lines:
        if line == ELIDE or len(line) <= WRAP:
            res.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        parts = textwrap.wrap(line.strip(), WRAP - indent - 2)
        res.append(" " * indent + parts[0])
        res.extend(" " * (indent + 2) + p for p in parts[1:])
    return res


def color_for(line):
    s = line.strip()
    for key in ("Verdict: ESCAPABLE", "Verdict: NO ESCAPE PATH PROVEN"):
        if s.startswith(key):
            return COLORS[key], True
    if s.startswith("CRITICAL ") and "INFO " in s:
        return FG, False
    first = s.split(" ")[0] if s else ""
    if first in COLORS:
        return COLORS[first], True
    if s in ("Targets", "Host", "Summary", "Findings", "Active proof (canary probes)") or \
            s.startswith("EscapeArmed 0.1.0"):
        return (121, 192, 255), True
    if s.startswith("/rules/") and s.endswith("Ok"):
        return (63, 185, 80), True
    return FG, False


def render(name, title, lines):
    lines = wrap(lines)
    lh, pad, bar = 26, 26, 40
    cw = FONT.getlength("M")
    width = int(max(len(l) for l in lines if l != ELIDE) * cw + pad * 2)
    width = max(width, 900)
    height = bar + pad * 2 + lh * len(lines)
    img = Image.new("RGB", (width + 40, height + 40), (240, 243, 246))
    d = ImageDraw.Draw(img)
    x0, y0 = 20, 20
    d.rounded_rectangle([x0, y0, x0 + width, y0 + height], 12, fill=BG)
    d.rounded_rectangle([x0, y0, x0 + width, y0 + bar], 12, fill=(33, 38, 45))
    d.rectangle([x0, y0 + bar - 12, x0 + width, y0 + bar], fill=(33, 38, 45))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([x0 + 16 + i * 22, y0 + 14, x0 + 28 + i * 22, y0 + 26], fill=c)
    tw = d.textlength(title, font=UI)
    d.text((x0 + (width - tw) / 2, y0 + 11), title, font=UI, fill=(160, 168, 178))
    y = y0 + bar + pad
    for line in lines:
        if line == ELIDE:
            d.text((x0 + pad, y), "  ...", font=FONT, fill=DIM)
        else:
            col, bold = color_for(line)
            s = line.lstrip()
            lead = len(line) - len(s)
            first, _, rest = s.partition(" ")
            if col != FG and first in COLORS and not s.startswith("Verdict"):
                d.text((x0 + pad + lead * cw, y), first, font=BOLD, fill=col)
                d.text((x0 + pad + (lead + len(first)) * cw, y), " " + rest, font=FONT, fill=FG)
            else:
                d.text((x0 + pad + lead * cw, y), s, font=BOLD if bold else FONT, fill=col)
        y += lh
    img.save(os.path.join(OUT, name))
    print("wrote", name, img.size)


FIGS = [
    ("prove-vulnapp.png", "examples/prove-vulnapp.txt",
     "examples/prove-vulnapp.txt", [(1, 13), (45, 73)]),
    ("prove-sneaky.png", "examples/prove-sneaky.txt",
     "examples/prove-sneaky.txt", [(1, 17), (22, 24), (39, 63)]),
    ("prove-hardened.png", "examples/prove-hardened.txt",
     "examples/prove-hardened.txt", [(1, 13), (22, 46)]),
    ("kyverno-check.png", "examples/kyverno-check.txt", "examples/kyverno-check.txt", [(1, 11)]),
    ("falco-check.png", "examples/falco-check.txt", "examples/falco-check.txt", [(1, 3)]),
]

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, title, path, ranges in FIGS:
        render(name, title, select(path, ranges))
