#!/usr/bin/env python3
"""
Build a JSON map of PIA region IDs -> {city, country, lat, lng} by combining:

  1. The live PIA WireGuard server list (the same one piaproxy itself
     consumes), which gives us the canonical list of region IDs like
     ``us_seattle``, ``france``, ``aus_melbourne`` and an ISO 3166-1
     alpha-2 country code per region.
  2. OpenAI, asked to pick the representative city for each region (PIA
     region IDs are sometimes city-named, sometimes state-named, and
     sometimes country-level — the model picks a sensible exit city).
  3. GeoNames ``cities5000`` (cities with population >= 5000), which
     provides authoritative lat/long and a stable ``geonameid`` for the
     chosen city.

Output: a JSON file (default ``regions.json``) at the repo root, sorted
by region ID, that the maintainer can commit.

Required env:
    OPENAI_API_KEY   OpenAI API key.

Optional env:
    OPENAI_MODEL     Model to use. Default: gpt-5.4-mini.
    REGIONS_OUT      Output path. Default: regions.json.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import unicodedata
import urllib.request
import zipfile

from openai import OpenAI

PIA_SERVER_LIST = "https://serverlist.piaservers.net/vpninfo/servers/v6"
CITIES5000_URL = "https://download.geonames.org/export/dump/cities5000.zip"

OUTPUT_PATH = os.environ.get("REGIONS_OUT", "regions.json")
MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.4-mini")


def fetch_pia_regions() -> list[dict]:
    """Fetch PIA's public server list and return the raw region records."""
    req = urllib.request.Request(
        PIA_SERVER_LIST,
        headers={"User-Agent": "piaproxy-regions-builder/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read()
    # PIA returns "<json>\n<signature>\n" — only the first line is JSON.
    nl = data.index(b"\n")
    payload = json.loads(data[:nl])
    return payload.get("regions", [])


_CITIES_COLS = [
    "geonameid", "name", "asciiname", "alternatenames",
    "latitude", "longitude", "feature_class", "feature_code",
    "country_code", "cc2", "admin1_code", "admin2_code",
    "admin3_code", "admin4_code", "population", "elevation",
    "dem", "timezone", "modification_date",
]


def fetch_cities5000() -> list[dict]:
    """Download and parse GeoNames cities5000.zip."""
    req = urllib.request.Request(
        CITIES5000_URL,
        headers={"User-Agent": "piaproxy-regions-builder/1.0"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        zdata = r.read()
    with zipfile.ZipFile(io.BytesIO(zdata)) as z:
        name = next(n for n in z.namelist() if n.endswith(".txt"))
        with z.open(name) as f:
            text = f.read().decode("utf-8")
    out: list[dict] = []
    reader = csv.reader(io.StringIO(text), delimiter="\t", quoting=csv.QUOTE_NONE)
    for row in reader:
        if not row or len(row) < len(_CITIES_COLS):
            continue
        d = dict(zip(_CITIES_COLS, row))
        try:
            d["latitude"] = float(d["latitude"])
            d["longitude"] = float(d["longitude"])
            d["population"] = int(d.get("population") or 0)
        except ValueError:
            continue
        out.append(d)
    return out


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s or "")
    s = s.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def lookup_city(
    cities: list[dict],
    country_iso2: str,
    city_name: str,
    admin1: str | None = None,
) -> dict | None:
    """Find the best cities5000 row matching (country, city[, admin1])."""
    cc = (country_iso2 or "").upper()
    target = _norm(city_name)
    if not cc or not target:
        return None
    pool = [c for c in cities if c["country_code"].upper() == cc]
    if not pool:
        return None

    exact = [
        c for c in pool
        if _norm(c["name"]) == target or _norm(c["asciiname"]) == target
    ]
    if not exact:
        alt: list[dict] = []
        for c in pool:
            alts = (c.get("alternatenames") or "").split(",")
            if any(_norm(a) == target for a in alts if a):
                alt.append(c)
        exact = alt

    if exact:
        if admin1:
            with_admin = [c for c in exact if c.get("admin1_code") == admin1]
            if with_admin:
                exact = with_admin
        return max(exact, key=lambda c: c["population"])

    sub = [c for c in pool if target and target in _norm(c["asciiname"])]
    if sub:
        return max(sub, key=lambda c: c["population"])
    return None


def country_largest_city(cities: list[dict], country_iso2: str) -> dict | None:
    cc = (country_iso2 or "").upper()
    pool = [
        c for c in cities
        if c["country_code"].upper() == cc
        and c.get("feature_code", "").startswith("PPL")
    ]
    if not pool:
        return None
    return max(pool, key=lambda c: c["population"])


_RESOLVER_SCHEMA = {
    "name": "RegionLocation",
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "city": {
                "type": "string",
                "description": (
                    "English name of a real city present in GeoNames "
                    "(prefer the city's common English name, e.g. "
                    "'Tokyo', 'Frankfurt am Main', 'San Jose')."
                ),
            },
            "country_iso2": {
                "type": "string",
                "minLength": 2,
                "maxLength": 2,
                "description": "ISO 3166-1 alpha-2 country code, uppercase.",
            },
            "admin1": {
                "type": "string",
                "description": (
                    "Optional ISO 3166-2 / GeoNames admin1 code (e.g. "
                    "'WA' for Washington state, 'CA' for California, "
                    "'07' for Bavaria). Leave empty if unsure."
                ),
            },
            "country_level": {
                "type": "boolean",
                "description": (
                    "True if the PIA region is country-wide (the id/name "
                    "names a country, not a city), in which case 'city' "
                    "should be the country's most representative VPN "
                    "exit city (typically the largest or capital)."
                ),
            },
        },
        "required": ["city", "country_iso2", "admin1", "country_level"],
    },
    "strict": True,
}


def resolve_via_openai(client: OpenAI, region: dict) -> dict:
    """Ask OpenAI to map a PIA region to (city, iso2, admin1)."""
    system = (
        "You map Private Internet Access (PIA) VPN region identifiers to "
        "a real-world city. PIA region ids look like 'us_seattle', "
        "'us_oregon-pf', 'aus_melbourne', 'france', 'kr_south_korea-pf'. "
        "Some are city-specific, some are state/region-specific, some "
        "are country-level. Always reply with a JSON object matching "
        "the schema. Use a recognizable city name that GeoNames would "
        "have under the cities5000 dataset. country_iso2 must be the "
        "ISO 3166-1 alpha-2 code, uppercase. If the region is "
        "country-level, set country_level=true and choose that "
        "country's largest or most VPN-representative city."
    )
    user = (
        f"PIA region:\n"
        f"  id: {region.get('id', '')}\n"
        f"  name: {region.get('name', '')}\n"
        f"  country: {region.get('country', '')}\n"
    )
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        response_format={"type": "json_schema", "json_schema": _RESOLVER_SCHEMA},
        temperature=0,
    )
    return json.loads(resp.choices[0].message.content)


def main() -> int:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY not set", file=sys.stderr)
        return 1
    client = OpenAI(api_key=api_key)

    print("Fetching PIA region list...", file=sys.stderr)
    regions = fetch_pia_regions()
    print(f"  {len(regions)} regions", file=sys.stderr)
    if not regions:
        print("PIA returned no regions", file=sys.stderr)
        return 1

    print("Downloading GeoNames cities5000...", file=sys.stderr)
    cities = fetch_cities5000()
    print(f"  {len(cities)} cities loaded", file=sys.stderr)

    out: dict[str, dict] = {}
    failed: list[str] = []
    sorted_regions = sorted(regions, key=lambda r: r.get("id", ""))
    for i, r in enumerate(sorted_regions, 1):
        rid = r.get("id", "")
        if not rid:
            continue
        print(f"[{i}/{len(sorted_regions)}] {rid} "
              f"({r.get('name', '')!r}, country={r.get('country', '')})",
              file=sys.stderr)
        try:
            hint = resolve_via_openai(client, r)
        except Exception as e:
            print(f"  openai failed: {e}", file=sys.stderr)
            failed.append(rid)
            continue

        # Prefer the country code OpenAI returned, but fall back to PIA's
        # if the model gave us nothing usable.
        cc = (hint.get("country_iso2") or r.get("country") or "").upper()
        admin1 = (hint.get("admin1") or "").strip() or None

        match = lookup_city(cities, cc, hint.get("city", ""), admin1)
        if match is None and admin1:
            match = lookup_city(cities, cc, hint.get("city", ""), None)
        if match is None and hint.get("country_level"):
            match = country_largest_city(cities, cc)
        if match is None:
            print(f"  no cities5000 match for {hint!r}", file=sys.stderr)
            failed.append(rid)
            continue

        out[rid] = {
            "pia_name": r.get("name"),
            "pia_country": r.get("country"),
            "city": match["asciiname"],
            "country": match["country_code"],
            "admin1": match.get("admin1_code") or None,
            "lat": round(match["latitude"], 5),
            "lng": round(match["longitude"], 5),
            "geonameid": int(match["geonameid"]),
            "country_level": bool(hint.get("country_level")),
        }
        print(
            f"  -> {out[rid]['city']}, {out[rid]['country']}"
            f"{' (' + out[rid]['admin1'] + ')' if out[rid]['admin1'] else ''} "
            f"@ {out[rid]['lat']}, {out[rid]['lng']}",
            file=sys.stderr,
        )

    payload = {
        "_generated_by": "scripts/build_regions.py",
        "_pia_source": PIA_SERVER_LIST,
        "_cities_source": CITIES5000_URL,
        "_model": MODEL,
        "regions": out,
    }
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
    print(
        f"Wrote {OUTPUT_PATH}: {len(out)} ok, {len(failed)} failed "
        f"({', '.join(failed) if failed else 'none'})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
