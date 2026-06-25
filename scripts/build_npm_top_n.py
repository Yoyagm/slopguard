#!/usr/bin/env python3
"""Script de procedencia: genera el dataset top-N de npm (H4-T10, C3, ADR-3).

Procedencia
-----------
Fuente primaria — npm downloads API (api.npmjs.org/downloads/point, dominio publico):
  Proporciona el ranking de descargas reales para un rango de fechas fijo.
  Al especificar --week YYYY-MM-DD el rango es deterministico:
  misma fecha -> mismos datos historicos -> mismo ranking -> mismo artefacto.

  Limitacion tecnica: el endpoint bulk solo acepta paquetes NO scoped; los scoped
  (@scope/name) deben consultarse individualmente o se omiten del ranking de descargas.

Seed (dos capas, en orden de prioridad):
  1. Lista de referencia conocida (_BASELINE): ~500 nombres de paquetes muy populares
     por ecosistema (React, Vue, Angular, utilidades, herramientas de build, testing...).
     Garantiza que los mas descargados de conocimiento comun esten siempre en el corpus.
  2. npm registry search API (registry.npmjs.org/-/v1/search): descubrimiento adicional
     via multiples terminos de busqueda (frameworks, categorias). Complementa el baseline
     con paquetes relevantes pero menos conocidos. Resultados ordenados por popularidad npm.

Ranking final (para unscoped):
  npm downloads API bulk: rankea los candidatos unscoped por descargas reales en el
  rango fijo. Candidatos sin datos quedan al final. Los scoped se incluyen segun el
  orden de descubrimiento (baseline primero, luego seed).

Salida
------
    core/dataset/npm_top_8k.json    -- artefacto embebido con nombres normalizados
    core/dataset/npm_top_8k.sha256  -- digest SHA-256 del .json (verificado al arranque)

Uso
---
    python scripts/build_npm_top_n.py [--n 8000] [--week YYYY-MM-DD]

En runtime/CI no se requiere red: el .json esta embebido y verificado con SHA-256 via
load_top_n_npm() (H4-T11, R5.2/R5.4). El script solo corre como herramienta de build.

Normalizacion
-------------
Regla npm (§3.4): strip()+lower(); @scope/name -> normaliza segmentos, preserva /.
Sin colapso PEP 503 de ._- (eso es PyPI, R3.4).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Constantes de red
# ---------------------------------------------------------------------------

_NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
_NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point"
_SEARCH_PAGE_SIZE = 250
_DOWNLOADS_BATCH = 128   # maximo de la API npm downloads para unscoped
_MAX_URL_LEN = 4000      # limite conservador de longitud de URL
_HTTP_TIMEOUT = 30
_RETRY_WAIT = 2.0
_MAX_RETRIES = 3

# ---------------------------------------------------------------------------
# Baseline: paquetes npm de referencia conocida.
# Garantizan cobertura de los mas descargados mas alla de lo que surfea
# la busqueda tematica. Fuente: conocimiento del ecosistema npm (dominios
# publicos, no secretos). El ranking real se decide via downloads API.
# ---------------------------------------------------------------------------

_BASELINE: list[str] = [
    # Core runtime / poly fills
    "tslib", "core-js", "regenerator-runtime", "es-module-shims",
    "whatwg-fetch", "cross-fetch", "node-fetch", "isomorphic-fetch",
    "abortcontroller-polyfill",
    # Tipos de fundamento
    "@types/node", "@types/react", "@types/react-dom", "@types/lodash",
    "@types/express", "@types/jest", "@types/mocha", "@types/chai",
    "@types/sinon", "@types/body-parser", "@types/cors", "@types/morgan",
    "@types/webpack", "@types/babel__core", "@types/uuid",
    "@types/fs-extra", "@types/glob", "@types/semver",
    # React y su ecosistema
    "react", "react-dom", "react-is", "react-refresh",
    "react-router", "react-router-dom",
    "react-redux", "redux", "redux-thunk", "reselect",
    "react-query", "@tanstack/react-query",
    "zustand", "jotai", "recoil", "mobx", "mobx-react",
    "react-hook-form", "formik", "yup",
    "styled-components", "@emotion/react", "@emotion/styled",
    "classnames", "clsx",
    "react-helmet", "react-helmet-async",
    "react-beautiful-dnd", "react-dnd",
    "react-spring", "framer-motion",
    "react-icons", "react-spinners",
    "react-toastify", "notistack",
    "react-i18next", "i18next",
    "react-testing-library", "@testing-library/react",
    "@testing-library/user-event", "@testing-library/jest-dom",
    "prop-types",
    # Next.js
    "next", "next-auth", "@next/font", "@next/bundle-analyzer",
    # Vue y su ecosistema
    "vue", "vue-router", "vuex", "pinia",
    "@vue/test-utils", "nuxt", "@nuxt/kit",
    "vuetify", "element-ui", "element-plus",
    # Angular
    "@angular/core", "@angular/common", "@angular/forms",
    "@angular/router", "@angular/platform-browser",
    "@angular/cli", "@angular/compiler", "@angular/animations",
    "rxjs", "zone.js",
    "@ngrx/store", "@ngrx/effects",
    # Svelte / Astro / Solid
    "svelte", "@sveltejs/kit",
    "astro", "@astrojs/react",
    "solid-js", "@solidjs/router",
    # Build tools
    "webpack", "webpack-cli", "webpack-dev-server",
    "webpack-merge", "html-webpack-plugin",
    "css-loader", "style-loader", "file-loader",
    "babel-loader", "ts-loader",
    "vite", "@vitejs/plugin-react", "@vitejs/plugin-vue",
    "rollup", "rollup-plugin-node-resolve",
    "@rollup/plugin-node-resolve", "@rollup/plugin-commonjs",
    "@rollup/plugin-json", "@rollup/plugin-typescript",
    "esbuild", "esbuild-register",
    "parcel",
    "turbopack",
    # Babel y plugins
    "@babel/core", "@babel/cli", "@babel/preset-env",
    "@babel/preset-react", "@babel/preset-typescript",
    "@babel/runtime", "@babel/plugin-transform-runtime",
    "@babel/parser", "@babel/traverse", "@babel/generator",
    "@babel/code-frame", "@babel/highlight",
    "babel-jest", "babel-eslint",
    # TypeScript y herramientas
    "typescript", "ts-node", "ts-jest",
    "@typescript-eslint/eslint-plugin",
    "@typescript-eslint/parser", "tsc-alias",
    # Linters / formatters
    "eslint", "eslint-config-prettier", "eslint-plugin-react",
    "eslint-plugin-import", "eslint-plugin-node",
    "eslint-plugin-jsx-a11y", "eslint-plugin-react-hooks",
    "@eslint/js", "globals",
    "prettier", "prettier-eslint",
    "stylelint", "stylelint-config-standard",
    "husky", "lint-staged",
    # Testing
    "jest", "jest-cli", "jest-circus",
    "@jest/globals", "@jest/types", "jest-environment-jsdom",
    "vitest", "@vitest/ui",
    "mocha", "chai", "sinon", "sinon-chai",
    "jasmine", "karma", "karma-jasmine",
    "cypress", "playwright", "@playwright/test",
    "puppeteer", "cheerio",
    "supertest", "nock",
    "enzyme", "@wojtekmaj/enzyme-adapter-react-17",
    "istanbul", "nyc", "c8", "v8-to-istanbul",
    # Backend / Node.js
    "express", "koa", "fastify", "hapi",
    "@nestjs/core", "@nestjs/common", "@nestjs/platform-express",
    "connect", "body-parser", "cors", "morgan", "helmet",
    "compression", "cookie-parser", "express-session",
    "passport", "passport-local", "passport-jwt",
    "socket.io", "socket.io-client", "ws",
    "multer", "busboy",
    # HTTP / red
    "axios", "got", "node-fetch", "node-fetch-commonjs",
    "superagent", "request", "bent", "ky",
    "form-data", "follow-redirects",
    # Utilitarios fundamentales
    "lodash", "lodash-es", "lodash.merge", "lodash.get",
    "underscore", "ramda",
    "immer", "immutable",
    "rxjs",
    "async", "bluebird", "p-limit", "p-queue", "p-map",
    "uuid", "nanoid", "cuid", "cuid2",
    "ms", "ms.js",
    "chalk", "kleur", "picocolors", "ansi-colors", "colorette",
    "colors", "kleur",
    "commander", "yargs", "meow", "cac", "minimist", "nopt",
    "debug", "loglevel",
    "winston", "pino", "bunyan", "log4js",
    "semver", "compare-versions",
    "dotenv", "dotenv-expand",
    "cross-env", "env-cmd",
    "mkdirp", "rimraf", "del", "fs-extra", "graceful-fs",
    "glob", "fast-glob", "globby", "micromatch", "minimatch",
    "chokidar", "watchpack",
    "shelljs", "execa", "cross-spawn",
    "which", "find-up", "pkg-up",
    "yalc",
    "path", "path-to-regexp",
    "mime", "mime-types", "file-type",
    "node-uuid",
    "xml2js", "fast-xml-parser",
    "csv-parse", "papaparse",
    "archiver", "adm-zip", "jszip",
    "markdown-it", "marked", "remark",
    "jsonschema", "ajv", "joi", "zod",
    # DB / ORM
    "mongoose", "mongodb", "mongoose-paginate-v2",
    "sequelize", "pg", "pg-hstore", "mysql", "mysql2",
    "sqlite3", "better-sqlite3",
    "redis", "ioredis",
    "typeorm", "prisma", "@prisma/client",
    "knex", "objection",
    "neo4j-driver",
    # Auth
    "jsonwebtoken", "bcrypt", "bcryptjs",
    "argon2", "crypto-js",
    # Bundlers extra
    "terser", "uglify-js", "cssnano",
    "postcss", "autoprefixer", "tailwindcss",
    "sass", "node-sass", "less",
    # Monorepo
    "lerna", "nx", "turborepo", "@changesets/cli",
    # Misc herramientas de build
    "nodemon", "ts-watch", "pm2",
    "copy-webpack-plugin", "mini-css-extract-plugin",
    "source-map-loader", "thread-loader",
    "hard-source-webpack-plugin",
    # Scoped de babel
    "@babel/eslint-parser", "@babel/eslint-plugin",
    # Config tools
    "cosmiconfig", "lilconfig",
    "convict", "nconf",
    # Documentation
    "typedoc", "jsdoc",
    "storybook", "@storybook/react", "@storybook/vue",
    "@storybook/addon-essentials",
    # Misc popular
    "date-fns", "moment", "dayjs", "luxon",
    "numeral", "accounting",
    "lodash.debounce", "lodash.throttle",
    "d3", "d3-scale", "d3-shape",
    "chart.js", "recharts", "victory",
    "three", "babylonjs",
    "leaflet", "mapbox-gl",
    "tinymce", "quill", "slate",
    "socket.io-adapter",
    "cheerio", "jsdom",
    "puppeteer-core",
    "jest-mock",
    "stream", "through2", "readable-stream",
    "events", "event-emitter",
    "node-cron", "agenda",
    "sharp", "jimp",
    "ffmpeg-static",
    "node-gyp", "bindings",
    "nan",
    "node-addon-api",
    # Cloud / deployment
    "aws-sdk", "@aws-sdk/client-s3",
    "firebase", "firebase-admin",
    "@google-cloud/storage",
    "azure-storage",
    # Otros frameworks
    "hono", "elysia", "nitro", "h3",
    "remix", "@remix-run/node", "@remix-run/react",
    "sveltekit",
    # Testing utils
    "msw", "miragejs",
    "faker", "@faker-js/faker",
    "chance",
    # i18n
    "i18next", "react-i18next", "vue-i18n",
    "@lingui/core",
    # State management extra
    "xstate", "@xstate/react",
    "valtio",
    # UI component libraries
    "@mui/material", "@mui/icons-material",
    "@chakra-ui/react",
    "antd", "ant-design",
    "@radix-ui/react-dialog", "@radix-ui/react-popover",
    "shadcn",
    "bootstrap", "reactstrap",
    "bulma",
    # Code quality
    "sonarjs",
    "typescript-eslint",
]

# Terminos de busqueda complementarios (descubrimiento de paquetes adicionales)
_SEARCH_TERMS: list[str] = [
    "react", "vue", "angular", "svelte", "next", "nuxt", "astro", "remix",
    "webpack", "vite", "rollup", "esbuild", "parcel",
    "babel", "typescript",
    "jest", "vitest", "mocha", "cypress", "playwright",
    "express", "fastify", "koa", "nestjs",
    "axios", "lodash", "redux", "tailwindcss",
    "eslint", "prettier", "storybook", "turborepo",
]


# ---------------------------------------------------------------------------
# Normalizacion npm (copia local del nucleo §3.4)
# ---------------------------------------------------------------------------

def _normalize_npm_name(raw: str) -> str:
    """Normaliza un nombre npm: strip+lower, preservando la estructura scoped.

    Para nombres simples: strip().lower().
    Para scoped @scope/name: normaliza segmentos por separado, preserva / (§3.4).
    Sin colapso PEP 503 de ._- (eso es PyPI, R3.4). Idempotente (R3.2).
    """
    stripped = raw.strip()
    if stripped.startswith("@") and "/" in stripped:
        scope_part, _, name_part = stripped.partition("/")
        return f"{scope_part.strip().lower()}/{name_part.strip().lower()}"
    return stripped.lower()


# ---------------------------------------------------------------------------
# Red: fetch robusto con reintentos
# ---------------------------------------------------------------------------

def _http_get_json(url: str) -> object:
    """GET JSON con reintentos y User-Agent identificado. Devuelve None en fallo."""
    req = urllib.request.Request(  # noqa: S310 (https fijo, dominio publico)
        url,
        headers={
            "User-Agent": "slopguard-dataset-gen/1.0",
            "Accept": "application/json",
        },
    )
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310
                return json.loads(resp.read())
        except Exception as exc:
            if attempt < _MAX_RETRIES:
                print(
                    f"  ! intento {attempt}/{_MAX_RETRIES} fallido: {exc}; "
                    f"reintento en {_RETRY_WAIT}s",
                    file=sys.stderr,
                )
                time.sleep(_RETRY_WAIT)
    print(f"  ! URL fallida tras {_MAX_RETRIES} intentos: {url[:100]}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Seed: baseline + busqueda en npm registry
# ---------------------------------------------------------------------------

def _collect_seed(seed_count: int, terms: list[str]) -> list[str]:
    """Recolecta candidatos: baseline primero, luego descubrimiento via search API.

    El baseline garantiza los paquetes de referencia conocida. La busqueda
    complementa con paquetes adicionales hasta `seed_count` total.
    Retorna nombres sin normalizar, unicos, en orden de descubrimiento.
    """
    seen: set[str] = set()
    names: list[str] = []

    # Paso 1a: baseline de referencia conocida
    for raw in _BASELINE:
        norm_check = raw.strip()
        if norm_check and norm_check not in seen:
            seen.add(norm_check)
            names.append(raw)

    print(
        f"  baseline: {len(names)} paquetes de referencia conocida",
        file=sys.stderr,
    )

    # Paso 1b: descubrimiento via npm search API
    for term in terms:
        if len(names) >= seed_count:
            break
        offset = 0
        added_this_term = 0

        while len(names) < seed_count:
            params = urllib.parse.urlencode({
                "text": term,
                "size": _SEARCH_PAGE_SIZE,
                "from": offset,
            })
            url = f"{_NPM_SEARCH_URL}?{params}"
            payload = _http_get_json(url)
            if not isinstance(payload, dict):
                break
            objects = payload.get("objects")
            if not isinstance(objects, list) or not objects:
                break

            batch_added = 0
            for obj in objects:
                pkg = obj.get("package") if isinstance(obj, dict) else None
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name")
                if isinstance(name, str) and name and name not in seen:
                    seen.add(name)
                    names.append(name)
                    batch_added += 1

            added_this_term += batch_added
            if batch_added == 0 or len(objects) < _SEARCH_PAGE_SIZE:
                break
            offset += _SEARCH_PAGE_SIZE
            time.sleep(0.05)

        print(
            f"  [{term[:30]:30s}]: +{added_this_term:4d}  (total: {len(names):6d})",
            file=sys.stderr,
        )

    print(f"  seed total: {len(names)} candidatos unicos", file=sys.stderr)
    return names[:seed_count]


# ---------------------------------------------------------------------------
# Ranking por descargas (npm downloads API, solo unscoped en bulk)
# ---------------------------------------------------------------------------

def _week_range(monday: str) -> tuple[str, str]:
    """Calcula el rango lunes..domingo para la semana del `monday` dado."""
    start = datetime.date.fromisoformat(monday)
    end = start + datetime.timedelta(days=6)
    return start.isoformat(), end.isoformat()


def _fetch_downloads_batch(names: list[str], period: str) -> dict[str, int]:
    """Consulta descargas de un batch de paquetes NO-scoped para el periodo dado.

    Respeta el limite de longitud de URL (_MAX_URL_LEN) partiendo en sub-batches.
    Solo acepta paquetes NO scoped; los scoped deben omitirse antes de llamar.
    """
    base = f"{_NPM_DOWNLOADS_URL}/{period}/"
    result: dict[str, int] = {}
    sub_names: list[str] = []
    sub_encoded: list[str] = []

    def _flush_sub() -> None:
        if not sub_encoded:
            return
        url = base + ",".join(sub_encoded)
        payload = _http_get_json(url)
        if not isinstance(payload, dict):
            return
        for name, info in payload.items():
            if isinstance(info, dict):
                dl = info.get("downloads")
                if isinstance(dl, int) and dl > 0:
                    result[name] = dl
        sub_names.clear()
        sub_encoded.clear()

    for name in names:
        enc = urllib.parse.quote(name, safe="")
        trial_url = base + ",".join([*sub_encoded, enc])
        if sub_encoded and len(trial_url) > _MAX_URL_LEN:
            _flush_sub()
        sub_names.append(name)
        sub_encoded.append(enc)

    _flush_sub()
    return result


def _fetch_scoped_downloads_individual(scoped: list[str], period: str) -> dict[str, int]:
    """Obtiene descargas de paquetes scoped consultandolos individualmente.

    La API bulk no soporta scoped, pero el endpoint individual si. Se limita
    a los primeros 500 para no exceder el tiempo de ejecucion.
    """
    max_scoped = min(500, len(scoped))
    downloads: dict[str, int] = {}
    print(
        f"  consultando {max_scoped} scoped individualmente (de {len(scoped)})...",
        file=sys.stderr,
    )
    for i, name in enumerate(scoped[:max_scoped]):
        enc = urllib.parse.quote(name, safe="@/")
        url = f"{_NPM_DOWNLOADS_URL}/{period}/{enc}"
        payload = _http_get_json(url)
        if isinstance(payload, dict):
            dl = payload.get("downloads")
            if isinstance(dl, int) and dl > 0:
                downloads[name] = dl
        if (i + 1) % 100 == 0:
            print(f"    {i+1}/{max_scoped} scoped, con datos: {len(downloads)}", file=sys.stderr)
        time.sleep(0.05)
    print(f"  scoped con datos: {len(downloads)}/{max_scoped}", file=sys.stderr)
    return downloads


def _rank_by_downloads(candidates: list[str], period: str) -> list[str]:
    """Rankea candidatos por descargas reales en `period`.

    Estrategia:
    - Unscoped: consulta bulk (API lo soporta).
    - Scoped (hasta 500): consulta individual.
    - Combina y ordena todos por descargas desc (luego por nombre asc como desempate).
    - Candidatos sin datos quedan al final.
    """
    unscoped = [n for n in candidates if not n.startswith("@")]
    scoped = [n for n in candidates if n.startswith("@")]
    downloads: dict[str, int] = {}

    # Ranking de unscoped via bulk
    num_batches = math.ceil(len(unscoped) / _DOWNLOADS_BATCH)
    print(
        f"  ranking: {len(unscoped)} no-scoped en {num_batches} batches, "
        f"{len(scoped)} scoped (individual hasta 500)...",
        file=sys.stderr,
    )
    for i in range(0, len(unscoped), _DOWNLOADS_BATCH):
        batch = unscoped[i : i + _DOWNLOADS_BATCH]
        downloads.update(_fetch_downloads_batch(batch, period))
        done = min(i + _DOWNLOADS_BATCH, len(unscoped))
        batch_num = i // _DOWNLOADS_BATCH + 1
        if batch_num % 20 == 0 or batch_num == num_batches:
            print(
                f"    batch {batch_num}/{num_batches}: {done}/{len(unscoped)}, "
                f"con datos: {len(downloads)}",
                file=sys.stderr,
            )
        time.sleep(0.05)

    print(
        f"  unscoped con datos: {sum(1 for n in unscoped if n in downloads)}/{len(unscoped)}; "
        f"top5: {sorted(unscoped, key=lambda n: -downloads.get(n,0))[:5]}",
        file=sys.stderr,
    )

    # Ranking de scoped via individual
    scoped_downloads = _fetch_scoped_downloads_individual(scoped, period)
    downloads.update(scoped_downloads)

    # Ordenar todos juntos por descargas desc
    all_candidates = unscoped + scoped
    ranked = sorted(all_candidates, key=lambda n: (-downloads.get(n, 0), n))
    print(
        f"  top10 final (todos): {ranked[:10]}",
        file=sys.stderr,
    )
    return ranked


# ---------------------------------------------------------------------------
# Construccion del artefacto
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ArtifactParams:
    """Parametros de configuracion para construir el artefacto JSON."""

    n: int
    week: str
    period: str
    terms: list[str]
    baseline_count: int


def _build_artifact(ranked: list[str], params: _ArtifactParams) -> bytes:
    """Construye el artefacto JSON canonico (sort_keys, sin espacios) como bytes."""
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in ranked:
        norm = _normalize_npm_name(raw)
        if norm and norm not in seen:
            seen.add(norm)
            normalized.append(norm)
        if len(normalized) >= params.n:
            break

    normalized.sort()  # orden estable -> artefacto determinista en bytes

    period_start, period_end = params.period.split(":", maxsplit=1)
    artifact = {
        "schema": "slopguard.topn/1",
        "version": f"npm-top-{len(normalized)}-{params.week}",
        "generated_at": params.week,
        "provenance": {
            "sources": [
                {
                    "step": "seed-baseline",
                    "description": (
                        "Lista de referencia de paquetes npm muy populares por "
                        "conocimiento del ecosistema (React, Vue, Angular, utilidades, "
                        "herramientas de build/testing/backend). Garantiza cobertura "
                        "de los mas descargados independientemente del alcance de la busqueda."
                    ),
                    "count": params.baseline_count,
                },
                {
                    "step": "seed-search",
                    "description": (
                        "Descubrimiento adicional via npm registry search API oficial "
                        "(registry.npmjs.org/-/v1/search). Multiples terminos de busqueda "
                        "complementan el baseline con paquetes del ecosistema."
                    ),
                    "url": _NPM_SEARCH_URL,
                    "terms": params.terms,
                },
                {
                    "step": "rank",
                    "description": (
                        "Ranking por descargas reales via npm downloads API publica "
                        "(api.npmjs.org/downloads/point). Solo paquetes no-scoped en bulk; "
                        "scoped consultados individualmente (hasta 500). "
                        "Rango de fecha fijado para reproducibilidad."
                    ),
                    "url": _NPM_DOWNLOADS_URL,
                    "period": params.period,
                    "period_start": period_start,
                    "period_end": period_end,
                },
            ],
            "normalization": (
                "npm: strip()+lower(); @scope/name preserva /; "
                "sin colapso PEP503 de ._-"
            ),
            "count_requested": params.n,
            "extraction_date": params.week,
        },
        "count": len(normalized),
        "names": normalized,
    }
    canonical = json.dumps(
        artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return canonical.encode("utf-8")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Genera el dataset top-N npm para SlopGuard (H4-T10, C3, ADR-3). "
            "Requiere acceso a la red (herramienta de build; no ejecutar en runtime/CI)."
        ),
    )
    ap.add_argument("--n", type=int, default=8000,
                    help="Numero de paquetes a emitir (default: 8000).")
    ap.add_argument(
        "--week",
        default="2026-06-16",
        help=(
            "Lunes de la semana de referencia para el ranking de descargas (YYYY-MM-DD). "
            "Misma fecha -> mismo snapshot reproducible. Default: 2026-06-16."
        ),
    )
    ap.add_argument("--seed", type=int, default=20000,
                    help="Limite de candidatos a recolectar antes del ranking (default: 20000).")
    args = ap.parse_args()

    n: int = args.n
    week: str = args.week
    seed_count: int = args.seed

    try:
        ref_date = datetime.date.fromisoformat(week)
    except ValueError as exc:
        print(f"Error: --week debe ser YYYY-MM-DD: {exc}", file=sys.stderr)
        return 1

    if ref_date.weekday() != 0:
        print(
            f"Aviso: {week} no es lunes (weekday={ref_date.weekday()}); "
            "el rango de la semana puede no alinear con una semana ISO.",
            file=sys.stderr,
        )

    start_date, end_date = _week_range(week)
    period = f"{start_date}:{end_date}"

    print(
        f"=== build_npm_top_n: n={n}, semana={week}, seed_limit={seed_count} ===",
        file=sys.stderr,
    )
    print(f"  periodo de descargas: {period}", file=sys.stderr)
    print(
        f"  baseline: {len(_BASELINE)} entradas, terminos de busqueda: {len(_SEARCH_TERMS)}",
        file=sys.stderr,
    )

    # Paso 1: seed = baseline + descubrimiento via search
    print("\nPaso 1: recolectando candidatos (baseline + search)...", file=sys.stderr)
    candidates = _collect_seed(seed_count, _SEARCH_TERMS)
    if not candidates:
        print("Error: sin candidatos del seed.", file=sys.stderr)
        return 2

    # Paso 2: ranking por descargas
    print("\nPaso 2: ranking por descargas npm...", file=sys.stderr)
    ranked = _rank_by_downloads(candidates, period)

    # Paso 3: construir y emitir artefacto
    blob = _build_artifact(
        ranked,
        _ArtifactParams(
            n=n,
            week=week,
            period=period,
            terms=_SEARCH_TERMS,
            baseline_count=len(_BASELINE),
        ),
    )
    digest = hashlib.sha256(blob).hexdigest()

    out_dir = (
        Path(__file__).resolve().parent.parent
        / "src" / "slopguard" / "core" / "dataset"
    )
    json_path = out_dir / "npm_top_8k.json"
    sha_path = out_dir / "npm_top_8k.sha256"

    json_path.write_bytes(blob)
    sha_path.write_text(digest + "\n", encoding="utf-8")

    artifact = json.loads(blob)
    actual_count = artifact["count"]
    names_list = artifact["names"]

    print(f"\nOK semana={week}, periodo={period}", file=sys.stderr)
    print(f"OK {json_path}  ({actual_count} nombres, {len(blob)} bytes)", file=sys.stderr)
    print(f"OK sha256={digest}", file=sys.stderr)
    print(f"muestra: {names_list[:5]} ... {names_list[-3:]}", file=sys.stderr)

    # Salida estandar para consumo CI
    print(
        json.dumps(
            {
                "artifact": str(json_path),
                "sha256": digest,
                "count": actual_count,
                "week": week,
                "period": period,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
