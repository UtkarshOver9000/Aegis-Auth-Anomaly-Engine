"""
Draw the Alibi mark: a bold dark-red "@" with an iron chain wrapped diagonally around it.

    python scripts/make_logo.py
    # writes src/ittravel/dashboard/logo.svg, src/ittravel/dashboard/favicon.svg and docs/img/logo.svg

The chain runs from lower left to upper right. It lies in front of the "@" at the lower left and passes
behind the outer ring at the upper right (that arc is drawn again on top), which makes it read as wrapped.
"""

import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
C = 64.0  # centre of the 128 x 128 canvas
RING, BOWL = 45.0, 15.0  # radii of the outer ring and the inner bowl of the "@"
GAP_START, GAP_END = -22.0, 300.0  # the ring runs anticlockwise from the tail round to the lower-right gap
CHAIN_FROM, CHAIN_TO = (14.0, 108.0), (115.0, 22.0)
PITCH = 10.6  # distance between link centres


def at(angle_deg: float, r: float) -> tuple[float, float]:
    a = math.radians(angle_deg)
    return C + r * math.cos(a), C - r * math.sin(a)


def arc(r: float, a0: float, a1: float) -> str:
    """SVG path for an anticlockwise arc (in screen terms) from angle a0 to a1."""
    x0, y0 = at(a0, r)
    x1, y1 = at(a1, r)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    return f"M{x0:.2f} {y0:.2f} A{r} {r} 0 {large} 0 {x1:.2f} {y1:.2f}"


def glyph(stroke: str, width: float, extra: str = "") -> str:
    """The "@": outer ring, inner bowl, and the stem that curls out into the ring."""
    sx = C + BOWL
    tx, ty = at(GAP_START, RING)
    tail = (
        f"M{sx:.1f} {C - 17:.1f} V{C + 8:.1f} Q{sx + 0.6:.1f} {C + 19:.1f} {sx + 11:.1f} {C + 19:.1f} "
        f"Q{tx - 6:.1f} {ty + 4:.1f} {tx:.2f} {ty:.2f}"
    )
    return (
        f'<g fill="none" stroke="{stroke}" stroke-width="{width}" stroke-linecap="round" '
        f'stroke-linejoin="round" {extra}>'
        f'<path d="{arc(RING, GAP_START, GAP_END)}"/><circle cx="{C}" cy="{C}" r="{BOWL}"/><path d="{tail}"/></g>'
    )


def chain() -> str:
    (x0, y0), (x1, y1) = CHAIN_FROM, CHAIN_TO
    length = math.hypot(x1 - x0, y1 - y0)
    angle = math.degrees(math.atan2(y1 - y0, x1 - x0))
    n = int(length // PITCH)
    parts = []
    for i in range(n + 1):
        t = i * PITCH / length
        x, y = x0 + (x1 - x0) * t, y0 + (y1 - y0) * t
        place = f'transform="translate({x:.2f} {y:.2f}) rotate({angle:.1f})"'
        if i % 2 == 0:  # face-on link: an oval ring
            parts.append(f'<ellipse rx="8.2" ry="4.9" fill="none" stroke="#0b0c0e" stroke-width="5.2" {place}/>')
            parts.append(f'<ellipse rx="8.2" ry="4.9" fill="none" stroke="url(#iron)" stroke-width="3.2" {place}/>')
            parts.append(
                f'<ellipse rx="8.2" ry="4.9" fill="none" stroke="#f4f6f8" stroke-opacity=".55" stroke-width=".8" '
                f'stroke-dasharray="7 30" {place}/>'
            )
        else:  # edge-on link: seen side-on it is a bar threading through both neighbours
            parts.append(
                f'<line x1="-8.6" x2="8.6" y1="0" y2="0" stroke="#0b0c0e" stroke-width="5.4" '
                f'stroke-linecap="round" {place}/>'
            )
            parts.append(
                f'<line x1="-8.6" x2="8.6" y1="0" y2="0" stroke="url(#ironEdge)" stroke-width="3.4" '
                f'stroke-linecap="round" {place}/>'
            )
    return "\n    ".join(parts)


def logo() -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="Alibi">
  <title>Alibi</title>
  <defs>
    <linearGradient id="blood" gradientUnits="userSpaceOnUse" x1="22" y1="14" x2="106" y2="118">
      <stop offset="0" stop-color="#ef233c"/>
      <stop offset=".32" stop-color="#b5121b"/>
      <stop offset=".68" stop-color="#6a040f"/>
      <stop offset="1" stop-color="#370104"/>
    </linearGradient>
    <linearGradient id="iron" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#e9edf1"/>
      <stop offset=".45" stop-color="#8d96a0"/>
      <stop offset="1" stop-color="#2f353c"/>
    </linearGradient>
    <linearGradient id="ironEdge" gradientUnits="userSpaceOnUse" x1="10" y1="20" x2="118" y2="112">
      <stop offset="0" stop-color="#c9d0d7"/>
      <stop offset=".5" stop-color="#6c757f"/>
      <stop offset="1" stop-color="#3a4048"/>
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="2.2" flood-color="#000" flood-opacity=".65"/>
    </filter>
  </defs>
  <g filter="url(#shadow)">
    {glyph("#1a0204", 14.5)}
    {glyph("url(#blood)", 11)}
    {glyph("#ff6b6b", 1.4, 'stroke-opacity=".35" transform="translate(-1.2 -1.4)"')}
  </g>
  <g filter="url(#shadow)">
    {chain()}
  </g>
  <g fill="none" stroke-linecap="butt">
    <path d="{arc(RING, 28, 62)}" stroke="#1a0204" stroke-width="14.5"/>
    <path d="{arc(RING, 28, 62)}" stroke="url(#blood)" stroke-width="11"/>
  </g>
</svg>
"""


def favicon() -> str:
    """Small sizes: the same "@" and three chain links, no fine detail."""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  {glyph("#c1121f", 15)}
  <g stroke="#aeb6bf" stroke-width="7" fill="none" stroke-linecap="round" transform="rotate(-40.4 64 64)">
    <ellipse cx="44" cy="64" rx="13" ry="8"/><line x1="56" y1="64" x2="74" y2="64"/>
    <ellipse cx="86" cy="64" rx="13" ry="8"/>
  </g>
</svg>
"""


if __name__ == "__main__":
    text = logo()
    for path in (ROOT / "src/ittravel/dashboard/logo.svg", ROOT / "docs/img/logo.svg"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (ROOT / "src/ittravel/dashboard/favicon.svg").write_text(favicon(), encoding="utf-8")
    print("links:", text.count("<ellipse") // 3 + text.count("<line") // 2)
