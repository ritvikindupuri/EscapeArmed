"""Small SVG layout kit for engineering blog style architecture diagrams.

Stage bands, icon cards, orthogonal arrows with rounded corners, a label pill on
every arrow, and a legend. Shared by render.py; rendered with cairosvg."""

import base64

import cairosvg

FONT = "DejaVu Sans"
CARD_W, CARD_H = 196, 148
GRAY = "#64748B"
LINE = "#94A3B8"
INK = "#0F172A"


def png_uri(svg: str, size: int) -> str:
    png = cairosvg.svg2png(bytestring=svg.encode(), output_width=size, output_height=size)
    return "data:image/png;base64," + base64.b64encode(png).decode()


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text_w(s: str, size: float, bold: bool = False) -> float:
    return len(s) * size * (0.64 if bold else 0.6)


def defs(accents) -> str:
    out = ['<defs>',
           '<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="2" '
           'stdDeviation="3" flood-color="#0F172A" flood-opacity="0.10"/></filter>']
    for name, color in accents.items():
        out.append(f'<marker id="arr-{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
                   f'markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="{color}"/></marker>')
    out.append('</defs>')
    return "".join(out)


def band(x, y, w, h, title) -> str:
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="18" fill="#F1F5F9" stroke="#E2E8F0" '
            f'stroke-width="1.5"/>'
            f'<text x="{x + w / 2}" y="{y + 40}" text-anchor="middle" font-family="{FONT}" font-size="16" '
            f'font-weight="bold" letter-spacing="2" fill="#475569">{esc(title)}</text>')


def card(cx, cy, icon_svg, title, sub, border="#CBD5E1", dashed=False, badge_svg=None) -> str:
    x, y = cx - CARD_W / 2, cy - CARD_H / 2
    dash = ' stroke-dasharray="8 6"' if dashed else ""
    out = [f'<rect x="{x}" y="{y}" width="{CARD_W}" height="{CARD_H}" rx="14" fill="#FFFFFF" '
           f'stroke="{border}" stroke-width="2"{dash} filter="url(#shadow)"/>',
           f'<image x="{cx - 30}" y="{y + 16}" width="60" height="60" href="{png_uri(icon_svg, 128)}"/>',
           f'<text x="{cx}" y="{y + 104}" text-anchor="middle" font-family="{FONT}" font-size="19" '
           f'font-weight="bold" fill="{INK}">{esc(title)}</text>',
           f'<text x="{cx}" y="{y + 128}" text-anchor="middle" font-family="{FONT}" font-size="14" '
           f'fill="{GRAY}">{esc(sub)}</text>']
    if badge_svg:
        out.append(f'<image x="{x + CARD_W - 38}" y="{y + 10}" width="28" height="28" '
                   f'href="{png_uri(badge_svg, 64)}"/>')
    return "".join(out)


def path_d(pts, r=12) -> str:
    """Polyline with rounded corners."""
    d = f"M{pts[0][0]} {pts[0][1]}"
    for i in range(1, len(pts) - 1):
        (x0, y0), (x1, y1), (x2, y2) = pts[i - 1], pts[i], pts[i + 1]
        def toward(ax, ay, bx, by, dist):
            L = max(abs(bx - ax), abs(by - ay))
            k = min(dist, L / 2) / L if L else 0
            return ax + (bx - ax) * k, ay + (by - ay) * k
        ax, ay = toward(x1, y1, x0, y0, r)
        bx, by = toward(x1, y1, x2, y2, r)
        d += f" L{ax} {ay} Q{x1} {y1} {bx} {by}"
    d += f" L{pts[-1][0]} {pts[-1][1]}"
    return d


def pill(x, y, label, color=GRAY, bg="#FFFFFF", border="#E2E8F0") -> str:
    w = text_w(label, 14) + 18
    return (f'<rect x="{x - w / 2}" y="{y - 13}" width="{w}" height="26" rx="13" fill="{bg}" '
            f'stroke="{border}" stroke-width="1.2"/>'
            f'<text x="{x}" y="{y + 5}" text-anchor="middle" font-family="{FONT}" font-size="14" '
            f'fill="{color}">{esc(label)}</text>')


def arrow(pts, accent="flow", color=LINE, dashed=False, width=2.4) -> str:
    dash = ' stroke-dasharray="9 6"' if dashed else ""
    return (f'<path d="{path_d(pts)}" fill="none" stroke="{color}" stroke-width="{width}"{dash} '
            f'stroke-linejoin="round" marker-end="url(#arr-{accent})"/>')


def legend(x, y, items) -> str:
    """items: list of (kind, payload, label). kind: line, icon, card."""
    out = []
    cx = x
    for kind, payload, label in items:
        if kind == "line":
            color, dashed, accent = payload
            out.append(arrow([(cx, y), (cx + 52, y)], accent=accent, color=color, dashed=dashed))
            tx = cx + 64
        elif kind == "icon":
            out.append(f'<image x="{cx}" y="{y - 15}" width="30" height="30" href="{png_uri(payload, 64)}"/>')
            tx = cx + 40
        elif kind == "card":
            color, dashed = payload
            dash = ' stroke-dasharray="6 4"' if dashed else ""
            out.append(f'<rect x="{cx}" y="{y - 13}" width="40" height="26" rx="6" fill="#FFFFFF" '
                       f'stroke="{color}" stroke-width="2"{dash}/>')
            tx = cx + 52
        out.append(f'<text x="{tx}" y="{y + 5}" font-family="{FONT}" font-size="15" fill="#334155">'
                   f'{esc(label)}</text>')
        cx = tx + text_w(label, 15) + 44
    return "".join(out), cx
