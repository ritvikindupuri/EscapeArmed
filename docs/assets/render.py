"""Render the EscapeArmed logo and architecture diagram (docs/assets/*.png).

Requires cairosvg. Icons: simple-icons (CC0) for Docker, Kubernetes, GitHub, Linux;
CNCF artwork (Apache-2.0 / CC-BY-4.0) for Falco and Kyverno."""

import base64
import io
import os
import re

import cairosvg

HERE = os.path.dirname(os.path.abspath(__file__))
ICONS = os.path.join(HERE, "icons")
BRAND = {"docker": "#2496ED", "kubernetes": "#326CE5", "github": "#181717", "linux": "#222222"}

GENERIC = {
    "file": '<path d="M6 2h8l4 4v16H6z" fill="none" stroke="#475569" stroke-width="1.6" stroke-linejoin="round"/>'
            '<path d="M14 2v4h4" fill="none" stroke="#475569" stroke-width="1.6"/>'
            '<path d="M9 11h6M9 14h6M9 17h4" stroke="#2496ED" stroke-width="1.6" stroke-linecap="round"/>',
    "scan": '<circle cx="10" cy="10" r="6.5" fill="none" stroke="#1E3A8A" stroke-width="2"/>'
            '<path d="M15 15l6 6" stroke="#1E3A8A" stroke-width="2.4" stroke-linecap="round"/>'
            '<path d="M7 10h6M10 7v6" stroke="#F97316" stroke-width="1.6" stroke-linecap="round"/>',
    "catalog": '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z" fill="none" stroke="#1E3A8A" stroke-width="1.8" stroke-linejoin="round"/>'
               '<path d="M8.5 12l2.5 2.5 4.5-5" fill="none" stroke="#16A34A" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    "prove": '<circle cx="12" cy="12" r="9" fill="none" stroke="#DC2626" stroke-width="1.8"/>'
             '<circle cx="12" cy="12" r="5" fill="none" stroke="#DC2626" stroke-width="1.8"/>'
             '<circle cx="12" cy="12" r="1.6" fill="#DC2626"/>'
             '<path d="M12 1v4M12 19v4M1 12h4M19 12h4" stroke="#DC2626" stroke-width="1.8" stroke-linecap="round"/>',
    "gen": '<circle cx="12" cy="12" r="3.2" fill="none" stroke="#7C3AED" stroke-width="1.8"/>'
           '<path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1" stroke="#7C3AED" stroke-width="1.8" stroke-linecap="round"/>'
           '<circle cx="12" cy="12" r="7" fill="none" stroke="#7C3AED" stroke-width="1.8"/>',
    "report": '<rect x="4" y="3" width="16" height="18" rx="2" fill="none" stroke="#475569" stroke-width="1.6"/>'
              '<path d="M8 15v2M12 11v6M16 8v9" stroke="#F97316" stroke-width="2" stroke-linecap="round"/>',
}


def png_uri(svg: str, size: int) -> str:
    png = cairosvg.svg2png(bytestring=svg.encode(), output_width=size, output_height=size)
    return "data:image/png;base64," + base64.b64encode(png).decode()


def brand_icon(name: str) -> str:
    raw = open(os.path.join(ICONS, f"{name}.svg")).read()
    if name in BRAND:
        d = re.search(r'<path d="([^"]+)"', raw).group(1)
        raw = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
               f'<path d="{d}" fill="{BRAND[name]}"/></svg>')
    return raw


def generic_icon(name: str) -> str:
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">{GENERIC[name]}</svg>'


W, H = 1640, 960
CARD_W, CARD_H = 210, 150
FONT = "DejaVu Sans"

# (id, x_center, y_center, icon svg, title, subtitle, dashed)
NODES = [
    ("docker", 160, 310, brand_icon("docker"), "Containers", "and images", False),
    ("files", 160, 510, generic_icon("file"), "Dockerfile", "and compose", False),
    ("host", 160, 710, brand_icon("linux"), "Linux host", "runc, toolkit", False),
    ("scan", 490, 430, generic_icon("scan"), "Scanner", "25 rules", False),
    ("catalog", 490, 690, generic_icon("catalog"), "CVE catalog", "runc, NVIDIA", False),
    ("prove", 820, 430, generic_icon("prove"), "Canary prover", "opt in, --active", True),
    ("gen", 1150, 510, generic_icon("gen"), "Generator", "policy and reports", False),
    ("report", 1480, 240, generic_icon("report"), "Report", "text and JSON", False),
    ("github", 1480, 420, brand_icon("github"), "Code scanning", "SARIF", False),
    ("kyverno", 1480, 600, brand_icon("kyverno"), "Kyverno", "admission policy", False),
    ("falco", 1480, 780, brand_icon("falco"), "Falco", "runtime rules", False),
]
EDGES = [("docker", "scan"), ("files", "scan"), ("host", "scan"), ("scan", "prove"),
         ("prove", "gen"), ("gen", "report"), ("gen", "github"), ("gen", "kyverno"), ("gen", "falco")]
COLUMNS = [(160, "INPUTS"), (490, "ANALYZE"), (820, "PROVE"), (1150, "GENERATE"), (1480, "ENFORCE AND REPORT")]


def card(n) -> str:
    nid, cx, cy, icon, title, sub, dashed = n
    x, y = cx - CARD_W / 2, cy - CARD_H / 2
    dash = ' stroke-dasharray="8 6"' if dashed else ""
    stroke = "#DC2626" if dashed else "#CBD5E1"
    out = [f'<rect x="{x}" y="{y}" width="{CARD_W}" height="{CARD_H}" rx="16" fill="#FFFFFF" '
           f'stroke="{stroke}" stroke-width="2"{dash} filter="url(#shadow)"/>',
           f'<image x="{cx - 32}" y="{y + 18}" width="64" height="64" href="{png_uri(icon, 128)}"/>',
           f'<text x="{cx}" y="{y + 108}" text-anchor="middle" font-family="{FONT}" font-size="19" '
           f'font-weight="bold" fill="#0F172A">{title}</text>',
           f'<text x="{cx}" y="{y + 132}" text-anchor="middle" font-family="{FONT}" font-size="14" '
           f'fill="#64748B">{sub}</text>']
    return "\n".join(out)


def edge(a, b, pos) -> str:
    _, ax, ay, *_ = pos[a]
    _, bx, by, *_ = pos[b]
    x1, x2 = ax + CARD_W / 2, bx - CARD_W / 2 - 6
    if a == "catalog":
        return ""
    return (f'<path d="M{x1} {ay} C{x1 + 60} {ay}, {x2 - 60} {by}, {x2} {by}" fill="none" '
            f'stroke="#94A3B8" stroke-width="2.5" marker-end="url(#arrow)"/>')


def diagram() -> str:
    pos = {n[0]: n for n in NODES}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
             '<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" '
             'orient="auto"><path d="M0 0L10 5L0 10z" fill="#94A3B8"/></marker>'
             '<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="3" '
             'stdDeviation="4" flood-color="#0F172A" flood-opacity="0.12"/></filter></defs>',
             f'<rect width="{W}" height="{H}" fill="#F8FAFC"/>',
             f'<text x="{W / 2}" y="58" text-anchor="middle" font-family="{FONT}" font-size="28" '
             f'font-weight="bold" fill="#0F172A">Figure 1. EscapeArmed System Architecture</text>']
    for cx, label in COLUMNS:
        parts.append(f'<text x="{cx}" y="112" text-anchor="middle" font-family="{FONT}" font-size="14" '
                     f'font-weight="bold" letter-spacing="2" fill="#94A3B8">{label}</text>')
    for a, b in EDGES:
        parts.append(edge(a, b, pos))
    # catalog feeds the scanner from below
    _, sx, sy, *_ = pos["scan"]
    _, kx, ky, *_ = pos["catalog"]
    parts.append(f'<path d="M{kx} {ky - CARD_H / 2} L{sx} {sy + CARD_H / 2 + 6}" stroke="#94A3B8" '
                 f'stroke-width="2.5" marker-end="url(#arrow)"/>')
    # docker exec link: prover reaches into the target container
    _, px, py, *_ = pos["prove"]
    parts.append(f'<text x="{px}" y="{py + CARD_H / 2 + 34}" text-anchor="middle" font-family="{FONT}" '
                 f'font-size="14" fill="#DC2626">docker exec, read only canaries</text>')
    parts.append(f'<text x="{(sx + px) / 2}" y="{sy - 14}" text-anchor="middle" font-family="{FONT}" '
                 f'font-size="13" fill="#64748B">findings</text>')
    for n in NODES:
        parts.append(card(n))
    # Kyverno runs on Kubernetes: small badge in the card corner
    _, yx, yy, *_ = pos["kyverno"]
    parts.append(f'<image x="{yx + CARD_W / 2 - 40}" y="{yy - CARD_H / 2 + 12}" width="28" height="28" '
                 f'href="{png_uri(brand_icon("kubernetes"), 64)}"/>')
    # Docker badge on the prover: it works through the Docker API
    _, px2, py2, *_ = pos["prove"]
    parts.append(f'<image x="{px2 + CARD_W / 2 - 40}" y="{py2 - CARD_H / 2 + 12}" width="28" height="28" '
                 f'href="{png_uri(brand_icon("docker"), 64)}"/>')
    parts.append(f'<text x="{W / 2}" y="{H - 28}" text-anchor="middle" font-family="{FONT}" font-size="13" '
                 f'fill="#94A3B8">Docker, Kubernetes, GitHub and Linux icons: Simple Icons (CC0). '
                 f'Falco and Kyverno icons: CNCF artwork.</text>')
    parts.append("</svg>")
    return "\n".join(parts)


if __name__ == "__main__":
    svg = diagram()
    open(os.path.join(HERE, "architecture.svg"), "w").write(svg)
    cairosvg.svg2png(bytestring=svg.encode(), write_to=os.path.join(HERE, "architecture.png"),
                     output_width=W * 2, output_height=H * 2)
    logo = open(os.path.join(HERE, "logo.svg")).read()
    cairosvg.svg2png(bytestring=logo.encode(), write_to=os.path.join(HERE, "logo.png"),
                     output_width=512, output_height=512)
    print("rendered architecture.png, architecture.svg, logo.png")
