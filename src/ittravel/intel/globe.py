"""
Globe textures rendered on the server from the snapshot.

Each metric becomes one equirectangular image: the NASA Earth image with every state filled by
its bin colour and the state and country borders drawn on top. Browsers download one image
instead of painting 4,596 states themselves, which is what makes the globe usable on phones.
Images are cached per server instance and by the CDN until the next snapshot.

Bins: ColorBrewer YlOrRd, 6 classes (colour-blind safe). Zero gets the lightest class, positive
values are split into quantile classes, and states without data are grey.
"""

from __future__ import annotations

import bisect
import io
import json
from functools import cache, lru_cache
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from .service import _load

VENDOR = Path(__file__).resolve().parents[1] / "dashboard" / "vendor"
PALETTE = ["#ffffb2", "#fed976", "#feb24c", "#fd8d3c", "#f03b20", "#bd0026"]  # ColorBrewer YlOrRd-6
NO_DATA = "#9e9e9e"
MIN_ADDRESSES = 100_000  # a state needs this many IPv4 addresses before a per-million rate means anything
SIZES = (2048, 4096)

METRICS = {
    "malicious_ips": {"level": "state", "field": "m", "unit": "malware servers per million IP addresses"},
    "dns_resolvers": {"level": "state", "field": "d", "unit": "public DNS servers per million IP addresses"},
    "ransomware_victims": {"level": "country", "field": "ransomware_victims", "unit": "ransomware victims this week"},
    "confirmed_blocks": {
        "level": "country",
        "field": "confirmed_blocks",
        "unit": "websites confirmed blocked, last 30 days",
        "needs": "censorship_measurements",
    },
    "hosting_ipv4": {"level": "country", "field": "hosting_ipv4", "unit": "addresses on hosting / VPN networks"},
    "cable_landings": {"level": "country", "field": "cable_landings", "unit": "undersea cable landing stations"},
    "tor_exits": {"level": "country", "field": "tor_exits", "unit": "Tor exit relays"},
}


def _rgb(hex_color: str) -> tuple[int, int, int]:
    return tuple(int(hex_color[i : i + 2], 16) for i in (1, 3, 5))


def state_values(metric: str) -> list[float | None]:
    m = METRICS[metric]
    states, countries = _load("states.json"), _load("countries.json")
    if m["level"] == "state":
        return [s[m["field"]] / s["ip"] * 1e6 if s.get("ip", 0) >= MIN_ADDRESSES else None for s in states]
    out = []
    for s in states:
        c = countries.get(s["c"])
        out.append(None if c is None or (m.get("needs") and not c[m["needs"]]) else c[m["field"]])
    return out


def _unit_values(metric: str) -> list[float]:
    """The values the bins are cut from: states for state-level data, countries for country-level data."""
    m = METRICS[metric]
    if m["level"] == "state":
        return [v for v in state_values(metric) if v is not None]
    return [c[m["field"]] for c in _load("countries.json").values() if not m.get("needs") or c[m["needs"]]]


def _counts(metric: str) -> bool:
    return METRICS[metric]["level"] == "country"  # country-level metrics are whole-number counts


@cache
def bins(metric: str) -> list[float]:
    """Upper edges of the positive classes (the last class is open-ended)."""
    positive = [v for v in _unit_values(metric) if v > 0]
    if not positive:
        return []
    edges = np.quantile(positive, [0.2, 0.4, 0.6, 0.8]).tolist()
    edges = [float(np.ceil(e)) if _counts(metric) else round(e, 2) for e in edges]
    return sorted({e for e in edges if 0 < e < max(positive)})


def class_of(metric: str, value: float | None) -> int:
    """-1 = no data, 0 = zero, 1.. = positive classes."""
    if value is None:
        return -1
    if value <= 0:
        return 0
    return 1 + bisect.bisect_left(bins(metric), value)


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if v >= 100 else f"{v:,.2f}".rstrip("0").rstrip(".")


def legend(metric: str) -> dict:
    m, edges = METRICS[metric], bins(metric)
    rows = [{"color": PALETTE[0], "label": "0"}]
    lows = [0.0, *edges]
    for i, low in enumerate(lows):
        high = edges[i] if i < len(edges) else None
        if _counts(metric):
            first = int(low) + 1
            label = (
                f"{first:,} or more"
                if high is None
                else (f"{first:,}" if first == high else f"{first:,} to {int(high):,}")
            )
        else:
            label = (
                f"over {_fmt(low)}"
                if high is None
                else (f"up to {_fmt(high)}" if low == 0 else f"{_fmt(low)} to {_fmt(high)}")
            )
        rows.append({"color": PALETTE[min(i + 1, len(PALETTE) - 1)], "label": label})
    no_data = f"fewer than {MIN_ADDRESSES:,} IP addresses" if m["level"] == "state" else "no data"
    return {
        "metric": metric,
        "unit": m["unit"],
        "level": m["level"],
        "bins": rows,
        "no_data": {"color": NO_DATA, "label": no_data},
        "min_addresses": MIN_ADDRESSES,
    }


def top(metric: str, n: int = 10) -> list[dict]:
    m = METRICS[metric]
    if m["level"] == "state":
        states, countries = _load("states.json"), _load("countries.json")
        ranked = sorted(((v, s) for v, s in zip(state_values(metric), states, strict=True) if v), key=lambda t: -t[0])
        return [
            {
                "name": f"{s['n']}, {countries.get(s['c'], {}).get('name', s['c'])}",
                "value": round(v, 2),
                "count": s[m["field"]],
                "addresses": s["ip"],
            }
            for v, s in ranked[:n]
        ]
    countries = [c for c in _load("countries.json").values() if c[m["field"]] > 0]
    return [{"name": c["name"], "value": c[m["field"]]} for c in sorted(countries, key=lambda c: -c[m["field"]])[:n]]


def _project(ring: list, width: int) -> list[list[tuple[float, float]]]:
    """[[lat, lng], ...] -> pixel polygons; a ring that crosses the date line is drawn on both edges."""
    height = width / 2
    crosses = any(abs(ring[i][1] - ring[i - 1][1]) > 180 for i in range(1, len(ring)))
    pts = [((lng + 360 if crosses and lng < 0 else lng) + 180) / 360 * width for _, lng in ring]
    ys = [(90 - lat) / 180 * height for lat, _ in ring]
    polys = [list(zip(pts, ys, strict=True))]
    if crosses:
        polys.append([(x - width, y) for x, y in polys[0]])
    return polys


@lru_cache(maxsize=1)
def _country_lines() -> list[list[list[float]]]:
    """Country borders and coastlines (every arc of world-atlas countries-110m) as [[lat, lng], ...]."""
    topo = json.loads((VENDOR / "countries-110m.json").read_text())
    (sx, sy), (tx, ty) = topo["transform"]["scale"], topo["transform"]["translate"]
    lines = []
    for arc in topo["arcs"]:
        x = y = 0
        line = []
        for dx, dy in arc:
            x, y = x + dx, y + dy
            line.append([y * sy + ty, x * sx + tx])
        lines.append(line)
    return lines


@lru_cache(maxsize=2)
def _earth(width: int) -> Image.Image:
    img = Image.open(VENDOR / "img" / "earth-blue-marble.jpg").convert("RGB")
    return img if img.width == width else img.resize((width, width // 2), Image.LANCZOS)


@lru_cache(maxsize=len(METRICS) * len(SIZES))
def texture(metric: str, width: int) -> bytes:
    states = _load("states.json")
    overlay = Image.new("RGBA", (width, width // 2), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    fills = [(*_rgb(NO_DATA), 90), *[(*_rgb(c), 158) for c in PALETTE]]
    for s, v in zip(states, state_values(metric), strict=True):
        fill = fills[class_of(metric, v) + 1]
        for ring in s["r"]:
            for poly in _project(ring, width):
                draw.polygon(poly, fill=fill)
    thin = max(1, width // 4096)
    for s in states:
        for ring in s["r"]:
            for poly in _project(ring, width):
                draw.line([*poly, poly[0]], fill=(255, 255, 255, 80), width=thin)
    for line in _country_lines():
        for poly in _project(line, width):
            draw.line(poly, fill=(255, 255, 255, 235), width=2 * thin)
    img = Image.alpha_composite(_earth(width).convert("RGBA"), overlay).convert("RGB")
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=82, optimize=True, progressive=True)
    return buf.getvalue()


@lru_cache(maxsize=1)
def pick_map(width: int = 2048) -> bytes:
    """PNG where each state's pixels hold its index + 1 in red*256 + green, for hover and click lookup."""
    img = Image.new("RGB", (width, width // 2), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    for i, s in enumerate(_load("states.json"), start=1):
        for ring in s["r"]:
            for poly in _project(ring, width):
                draw.polygon(poly, fill=(i >> 8, i & 255, 0))
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


@lru_cache(maxsize=1)
def places() -> list[list]:
    """One row per state, in pick-map order: name, country, type, malware servers, DNS servers, IPv4 addresses."""
    return [[s["n"], s["c"], s["t"], s.get("m", 0), s.get("d", 0), s.get("ip", 0)] for s in _load("states.json")]


def state(index: int) -> dict:
    s = _load("states.json")[index]
    return {"name": s["n"], "country": s["c"], "type": s["t"], "rings": s["r"]}
