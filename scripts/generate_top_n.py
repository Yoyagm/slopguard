#!/usr/bin/env python3.11
"""Generador REPRODUCIBLE del dataset top-N de PyPI (T19).

Procedencia: descarga el ranking público "top-pypi-packages" de hugovk
(snapshot de descargas de los últimos 30 días, dominio público), toma los
primeros N proyectos, normaliza cada nombre con PEP 503 y emite:
  - core/dataset/pypi_top_10k.json   (artefacto embebido, versionado)
  - core/dataset/pypi_top_10k.sha256 (hashlib.sha256 del .json, para R3.9/NFR-Seg.7)

El artefacto es la entrada de `core/dataset/top_n.py::load_top_n` (T20), que
verifica el checksum al cargar y aborta con DatasetIntegrityError si no cuadra.

Uso:  python3.11 scripts/generate_top_n.py [--n 10000] [--date YYYY-MM-DD]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

# Fuentes canónicas (con espejo). Dominio público; solo nombres de paquetes.
SOURCES = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json",
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json",
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json",
)
_PEP503 = re.compile(r"[-_.]+")


def normalize_pep503(name: str) -> str:
    return _PEP503.sub("-", name).strip().lower()


def fetch_rows() -> tuple[str, list[dict]]:
    last_err: Exception | None = None
    for url in SOURCES:
        try:
            req = urllib.request.Request(  # noqa: S310 (fuente https fija, dominio publico)
                url, headers={"User-Agent": "slopguard-dataset-gen"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https fijo)
                payload = json.loads(resp.read().decode("utf-8"))
            rows = payload.get("rows") or payload.get("packages") or []
            if rows:
                return url, rows
        except Exception as exc:  # pragma: no cover - red
            last_err = exc
            print(f"  ! fallo {url}: {exc}", file=sys.stderr)
    raise SystemExit(f"No se pudo descargar el ranking top-PyPI: {last_err}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=10000)
    ap.add_argument("--date", default="2026-06-22")
    args = ap.parse_args()

    source, rows = fetch_rows()
    names: list[str] = []
    seen: set[str] = set()
    for row in rows:
        proj = row.get("project") or row.get("name")
        if not proj:
            continue
        norm = normalize_pep503(proj)
        if norm and norm not in seen:
            seen.add(norm)
            names.append(norm)
        if len(names) >= args.n:
            break

    names.sort()  # orden estable -> artefacto determinista
    artifact = {
        "schema": "slopguard.topn/1",
        "version": f"pypi-top-{len(names)}-{args.date}",
        "generated_at": args.date,
        "provenance": {
            "source": source,
            "description": "Ranking público de descargas PyPI (hugovk/top-pypi-packages, 30d).",
            "extraction_date": args.date,
            "normalization": "PEP 503 (lowercase, runs de [-_.] -> '-')",
            "count_requested": args.n,
        },
        "count": len(names),
        "names": names,
    }
    out_dir = Path(__file__).resolve().parent.parent / "src" / "slopguard" / "core" / "dataset"
    json_path = out_dir / "pypi_top_10k.json"
    sha_path = out_dir / "pypi_top_10k.sha256"
    # Bytes canónicos (sort_keys + sin espacios superfluos) para checksum estable.
    canonical = json.dumps(artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    blob = canonical.encode("utf-8")
    digest = hashlib.sha256(blob).hexdigest()
    json_path.write_bytes(blob)
    sha_path.write_text(digest + "\n", encoding="utf-8")
    print(f"OK fuente={source}")
    print(f"OK {json_path}  ({len(names)} nombres, {len(blob)} bytes)")
    print(f"OK sha256={digest}")
    # muestra
    print("muestra:", names[:8], "...", names[-3:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
