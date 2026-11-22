"""Render the EscapeArmed logo and architecture diagram (docs/assets/*.png).

Requires cairosvg. Icons: simple-icons (CC0) for Docker, Kubernetes, GitHub, Linux;
CNCF artwork (Apache-2.0 / CC-BY-4.0) for Falco and Kyverno."""

import base64
import io
import os
import re

import cairosvg

from diagram_kit import CARD_H, CARD_W, FONT, arrow, band, card, defs, legend, pill

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
    "model": '<path d="M12 3l9 4.5-9 4.5-9-4.5z" fill="none" stroke="#0EA5E9" stroke-width="1.7" stroke-linejoin="round"/>'
             '<path d="M3 12l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5" fill="none" stroke="#1E3A8A" stroke-width="1.7" stroke-linejoin="round"/>',
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



W, H = 1960, 1190
RED = "#DC2626"
ACCENTS = {"flow": "#94A3B8", "live": RED}

# id: (cx, cy)
P = {
    "docker": (170, 440), "files": (170, 630), "host": (170, 820),
    "model": (545, 630), "scan": (850, 630), "catalog": (850, 865),
    "target": (1170, 225), "prove": (1170, 430),
    "gen": (1470, 630),
    "report": (1810, 330), "github": (1810, 530), "kyverno": (1810, 730), "falco": (1810, 930),
}
HW, HH = CARD_W / 2, CARD_H / 2


def L(n):
    return P[n][0] - HW, P[n][1]


def R(n):
    return P[n][0] + HW, P[n][1]


def T(n):
    return P[n][0], P[n][1] - HH


def B(n):
    return P[n][0], P[n][1] + HH


def diagram() -> str:
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
             defs(ACCENTS), f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>']
    top, bh = 40, 1000
    for x, w, title in [(50, 240, "INPUTS"), (360, 650, "ANALYZE"), (1050, 240, "PROVE"),
                        (1350, 240, "GENERATE"), (1670, 280, "ENFORCE AND REPORT")]:
        parts.append(band(x, top, w, bh, title))

    labels = []
    bus_in = 418
    for n, lab in [("docker", "container config"), ("files", "file contents"), ("host", "host config")]:
        x1, y1 = R(n)
        parts.append(arrow([(x1, y1), (bus_in, y1), (bus_in, P["model"][1]), (L("model")[0] - 2, P["model"][1])]))
        labels.append(pill((x1 + bus_in) / 2, y1, lab))
    parts.append(arrow([R("model"), (L("scan")[0] - 2, P["scan"][1])]))
    labels.append(pill((R("model")[0] + L("scan")[0]) / 2, P["model"][1], "one model"))
    parts.append(arrow([T("catalog"), (P["scan"][0], B("scan")[1] + 2)]))
    labels.append(pill(P["scan"][0], (T("catalog")[1] + B("scan")[1]) / 2, "known fixes"))
    # scan mode: findings straight to the generator, under the prover lane
    parts.append(arrow([R("scan"), (L("gen")[0] - 2, P["gen"][1])]))
    labels.append(pill(P["prove"][0], P["gen"][1], "findings"))
    # prove mode
    sx, sy = T("scan")
    parts.append(arrow([(sx, sy), (sx, P["prove"][1]), (L("prove")[0] - 2, P["prove"][1])], accent="live",
                       color=RED, dashed=True))
    labels.append(pill((sx + L("prove")[0]) / 2, P["prove"][1], "opt-in proof", color=RED, border="#FCA5A5"))
    parts.append(arrow([T("prove"), (P["target"][0], B("target")[1] + 2)], accent="live", color=RED, dashed=True))
    labels.append(pill(P["prove"][0], (T("prove")[1] + B("target")[1]) / 2, "run probes", color=RED,
                       border="#FCA5A5"))
    gx = P["gen"][0]
    parts.append(arrow([R("prove"), (gx, P["prove"][1]), (gx, T("gen")[1] - 2)]))
    labels.append(pill((R("prove")[0] + gx) / 2 - 10, P["prove"][1], "proof"))
    bus_out = 1615
    for n, lab in [("report", "JSON"), ("github", "SARIF"), ("kyverno", "policy"), ("falco", "rules")]:
        y = P[n][1]
        parts.append(arrow([R("gen"), (bus_out, P["gen"][1]), (bus_out, y), (L(n)[0] - 2, y)]))
        labels.append(pill((bus_out + L(n)[0]) / 2, y, lab))

    k = brand_icon("kubernetes")
    cards = [
        ("docker", brand_icon("docker"), "Containers", "and images", {}),
        ("files", generic_icon("file"), "Dockerfile", "and compose", {}),
        ("host", brand_icon("linux"), "Linux host", "runc, NVIDIA kit", {}),
        ("model", generic_icon("model"), "Workload model", "one format per target", {}),
        ("scan", generic_icon("scan"), "Scanner", "25 escape rules", {}),
        ("catalog", generic_icon("catalog"), "CVE catalog", "runc, NVIDIA", {}),
        ("target", brand_icon("docker"), "Live container", "your target", {"border": RED, "dashed": True}),
        ("prove", generic_icon("prove"), "Canary prover", "opt in only", {"border": RED, "dashed": True}),
        ("gen", generic_icon("gen"), "Generator", "verdict and outputs", {}),
        ("report", generic_icon("report"), "Report", "CI exit code gate", {}),
        ("github", brand_icon("github"), "Code scanning", "SARIF alerts", {}),
        ("kyverno", brand_icon("kyverno"), "Kyverno", "blocks risky pods", {"badge_svg": k}),
        ("falco", brand_icon("falco"), "Falco", "runtime alerts", {}),
    ]
    for n, icon, title, sub, kw in cards:
        parts.append(card(*P[n], icon, title, sub, **kw))
    parts.extend(labels)

    leg, end = legend(0, 0, [
        ("line", ("#94A3B8", False, "flow"), "data flow"),
        ("line", (RED, True, "live"), "live probe, opt in"),
        ("card", (RED, True), "touches a live target"),
        ("icon", generic_icon("scan"), "EscapeArmed component"),
        ("icon", brand_icon("docker"), "external product"),
    ])
    lx = (W - end + 44) / 2
    parts.append(f'<g transform="translate({lx} 1090)">{leg}</g>')
    parts.append(f'<text x="{W / 2}" y="{H - 24}" text-anchor="middle" font-family="{FONT}" font-size="13" '
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
