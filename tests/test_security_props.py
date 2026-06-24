"""Propiedades estructurales de seguridad por ANALISIS ESTATICO (T37).

Estas pruebas NO ejercitan comportamiento: recorren el codigo fuente del paquete
con `ast`/`tomllib` y verifican invariantes que deben cumplirse "por construccion".
Cubren tres guardias trazados a EARS:

1. **No ejecucion ni import dinamico del codigo analizado** (NFR-Seg.1). El core NO
   usa `eval`/`exec`/`__import__` ni `importlib.import_module`/`importlib.__import__`
   con argumento dinamico (un `Name`/`Attribute`/`Subscript`/f-string proveniente del
   manifiesto). Esto es distinto del anti-eval de ruff/T02 (NFR-Seg.2): aqui el foco
   es que jamas se importe ni ejecute el codigo de un paquete que se esta analizando.

2. **Allowlist unico de red = {pypi.org}** (NFR-Priv.2, NFR-Costo.1). Solo `core/net`
   abre sockets/urllib (ningun cliente HTTP ni endpoint fuera de ahi); no hay URLs
   `http(s)://` hardcodeadas a hosts ajenos; no hay SDKs de terceros ni LLM; y la
   constante fijada `ALLOWED_HOSTS` es exactamente `{"pypi.org"}`.

3. **Cero dependencias de runtime** (NFR-Costo.1, NFR-Mant.2). `pyproject.toml`
   `[project].dependencies` es una lista vacia (solo stdlib).

Hito 2 (T21) anade dos guardias mas, trazados a ADR-09 y NFR-Seg.1/Priv.2:

5. **Allowlist GENERALIZADA por-instancia** (ADR-09, propiedad estatica 4). La base
   `ALLOWED_HOSTS` sigue anclada a `{pypi.org}`; el conjunto EFECTIVO de CUALQUIER
   instancia de `SecureHttpClient` (construida por las fuentes reales) ⊆
   `{pypi.org, api.osv.dev, depscope.dev}`; `depscope.dev` SOLO aparece con
   `enable_watchlist=true`; y el `_RejectRedirectHandler` valida contra el conjunto
   EFECTIVO inyectado (no la global). Se cubren los vectores SSRF del pentest (IPs
   internas, metadata cloud, encodings de IP, IPv6, userinfo, puerto, redirect chain
   cross-host): el allowlist efectivo y el redirect handler DEBEN rechazarlos todos.

6. **Aislamiento de Capa 3** (NFR-Seg.1/Seg.3/Priv.2). El subconjunto de modulos de
   Capa 3 (`core/threatintel/*` + `core/layers/layer3_threatintel`) NO ejecuta ni
   importa el codigo de paquetes analizados, no usa LLM/SDK de terceros, y el UNICO
   transporte de red (instanciacion de `urllib`/`socket`/cliente HTTP) sale de
   `core/net`; ninguna fuente construye su propio transporte fuera de esa frontera.

ANTI-VACUIDAD (critico). Cada analizador AST es una funcion PURA que recibe el codigo
fuente como `str`. Para CADA guardia hay (a) la asercion sobre el codigo REAL del
paquete y (b) una asercion gemela que PLANTA una violacion en un snippet en memoria
y exige que el mismo analizador la DETECTE. Un guardia que no puede fallar no vale:
las pruebas `*_detecta_violacion_plantada` son la evidencia de que el guardia muerde.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from slopguard.core.config import Config
from slopguard.core.errors import NetworkUnverifiableError
from slopguard.core.net import http_client as hc
from slopguard.core.net.http_client import SecureHttpClient
from slopguard.core.threatintel.registry import get_threatintel_source

# --------------------------------------------------------------------------- #
# Localizacion del codigo fuente y del manifiesto del proyecto
# --------------------------------------------------------------------------- #

_THIS_FILE = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent
_SRC_PKG = _PROJECT_ROOT / "src" / "slopguard"
_PYPROJECT = _PROJECT_ROOT / "pyproject.toml"

# Allowlist canonica: unico host de red permitido (NFR-Priv.2 / espejo de
# `core.net.http_client.ALLOWED_HOSTS`). Cualquier otro host literal es violacion.
ALLOWLIST: frozenset[str] = frozenset({"pypi.org"})

# Hosts de REFERENCIA/DISPLAY exentos del guardia de URLs literales (NFR-Priv.2).
# `osv.dev` NO es un destino de red: es el host canonico de la pagina del advisory
# (`https://osv.dev/vulnerability/<id>`) que `core/threatintel/osv.py` RECONSTRUYE
# para mostrar al humano. La red OSV real va a `api.osv.dev`, gateada por la
# allowlist efectiva del cliente HTTP (`extra_allowed_hosts`), nunca por este literal.
# El guardia debe distinguir host de transporte (prohibido) de host de display
# (legitimo): `osv.dev` se exime aqui, cualquier OTRO host ajeno se sigue detectando.
_DISPLAY_HOSTS: frozenset[str] = frozenset({"osv.dev"})

# Allowlist efectiva del detector de URLs literales = transporte permitido + display.
_URL_HOST_ALLOWLIST: frozenset[str] = ALLOWLIST | _DISPLAY_HOSTS

# Primitivas de ejecucion/import dinamico prohibidas como `Call` directo (NFR-Seg.1).
_FORBIDDEN_CALLS: frozenset[str] = frozenset({"eval", "exec", "__import__"})

# Primitivas de import dinamico de `importlib` (prohibidas SOLO con argumento dinamico).
_IMPORTLIB_DYNAMIC = frozenset({"import_module", "__import__"})

# Modulos de red de la stdlib: SOLO `core/net` puede importarlos (NFR-Priv.2).
_NETWORK_MODULES = frozenset(
    {"urllib", "socket", "ssl", "http.client", "asyncio", "ftplib", "telnetlib"}
)

# SDKs de terceros / LLM cuya mera importacion violaria NFR-Priv.2 / NFR-Costo.1.
_FORBIDDEN_THIRD_PARTY = frozenset(
    {
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "openai",
        "anthropic",
        "cohere",
        "google",
        "boto3",
        "pickle",
        "marshal",
    }
)

# Regex laxa para localizar literales de URL con esquema http(s) dentro de un string.
_URL_RE = re.compile(r"https?://[^\s'\"<>)]*", re.IGNORECASE)

# Hostname DNS sintacticamente valido (labels alfanumericos separados por puntos).
# Sirve para descartar "hosts" basura de prosa de docstrings (p.ej. 'http://,').
_DNS_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


# --------------------------------------------------------------------------- #
# Utilidades de recorrido del paquete
# --------------------------------------------------------------------------- #


def _iter_source_files() -> list[Path]:
    """Devuelve los .py del paquete (excluye __pycache__)."""
    return sorted(p for p in _SRC_PKG.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    """Ruta del modulo relativa a src/ para mensajes legibles."""
    return str(path.relative_to(_SRC_PKG.parent.parent))


def _is_under_core_net(path: Path) -> bool:
    """True si el .py vive dentro de src/slopguard/core/net/."""
    return (_SRC_PKG / "core" / "net") in path.parents or path.parent == (
        _SRC_PKG / "core" / "net"
    )


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """ids() de los nodos `Constant` que son docstrings de modulo/clase/funcion.

    Se excluyen del escaneo de URLs: la prosa de los docstrings contiene ejemplos
    como 'http://,' o 'https://[fe80::1/x' que NO son endpoints reales.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            doc = ast.get_docstring(node, clean=False)
            if doc is None:
                continue
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


# --------------------------------------------------------------------------- #
# GUARDIA 1 - Analizador AST: ejecucion / import dinamico (NFR-Seg.1)
# --------------------------------------------------------------------------- #


def _call_func_name(func: ast.expr) -> str | None:
    """Nombre simple de lo invocado: `eval` (Name) o `mod.import_module` (Attribute)."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_dynamic_arg(arg: ast.expr) -> bool:
    """True si el argumento NO es una cadena constante (es decir, dinamico).

    `importlib.import_module("json")` es estatico y aceptable; lo que se prohibe es
    `import_module(nombre)` / `import_module(f"{pkg}")`, donde `nombre` proviene del
    manifiesto y supondria importar el codigo de un paquete analizado (NFR-Seg.1).
    """
    return not (isinstance(arg, ast.Constant) and isinstance(arg.value, str))


def find_dynamic_exec_violations(source: str) -> list[str]:
    """Lista violaciones de NFR-Seg.1 en `source`. Vacia => limpio.

    Detecta:
    - `Call` directo a `eval`/`exec`/`__import__` (cualquier argumento).
    - `importlib.import_module(x)` / `importlib.__import__(x)` con `x` dinamico.
    - cualquier `import importlib` / `from importlib import ...` (defensa en
      profundidad: el core no necesita import dinamico en absoluto).

    Funcion PURA: opera solo sobre el texto recibido, sin tocar el filesystem.
    """
    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib" or alias.name.startswith("importlib."):
                    violations.append(f"import de importlib en linea {node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            if node.module is not None and (
                node.module == "importlib" or node.module.startswith("importlib")
            ):
                violations.append(f"from importlib import ... en linea {node.lineno}")
        elif isinstance(node, ast.Call):
            name = _call_func_name(node.func)
            if name in _FORBIDDEN_CALLS:
                violations.append(f"llamada prohibida a {name}() en linea {node.lineno}")
            elif name in _IMPORTLIB_DYNAMIC and node.args and _is_dynamic_arg(node.args[0]):
                violations.append(
                    f"import dinamico {name}(<no-constante>) en linea {node.lineno}"
                )
    return violations


# --------------------------------------------------------------------------- #
# GUARDIA 2 - Analizadores AST: frontera de red y hosts (NFR-Priv.2 / Costo.1)
# --------------------------------------------------------------------------- #


def _imported_top_modules(tree: ast.AST) -> list[tuple[str, int]]:
    """Modulos importados (nombre completo, linea) para `import` y `from ... import`."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            found.append((node.module, node.lineno))
    return found


def _matches_module(imported: str, target: str) -> bool:
    """True si `imported` es `target` o un submodulo suyo (`urllib` ~ `urllib.request`)."""
    return imported == target or imported.startswith(target + ".")


def find_network_import_violations(source: str, *, in_core_net: bool) -> list[str]:
    """Imports de red fuera de `core/net` (NFR-Priv.2). Vacia => limpio.

    Si `in_core_net` es True, los imports de red estan permitidos (es la frontera).
    Funcion PURA: el llamante decide la frontera; aqui solo se analiza el texto.
    """
    if in_core_net:
        return []
    tree = ast.parse(source)
    violations: list[str] = []
    for name, line in _imported_top_modules(tree):
        if any(_matches_module(name, mod) for mod in _NETWORK_MODULES):
            violations.append(f"import de red '{name}' fuera de core/net en linea {line}")
    return violations


def find_third_party_import_violations(source: str) -> list[str]:
    """Imports de SDKs de terceros/LLM o deserializacion insegura. Vacia => limpio.

    Cubre NFR-Priv.2 (sin LLM/SDK ajeno) y NFR-Costo.1 (sin deps). Funcion PURA.
    """
    tree = ast.parse(source)
    violations: list[str] = []
    for name, line in _imported_top_modules(tree):
        top = name.split(".")[0]
        if top in _FORBIDDEN_THIRD_PARTY:
            violations.append(f"import de tercero/inseguro '{name}' en linea {line}")
    return violations


def find_foreign_url_hosts(
    source: str, *, allowlist: frozenset[str] = _URL_HOST_ALLOWLIST
) -> list[str]:
    """Hosts de URLs literales (no-docstring) fuera del allowlist. Vacia => limpio.

    Escanea SOLO literales de cadena que no sean docstrings, extrae el host de cada
    URL `http(s)://...` y reporta los que (a) son hostnames DNS validos y (b) no
    pertenecen al allowlist. El allowlist por defecto suma a `{pypi.org}` (transporte)
    los hosts de DISPLAY (`osv.dev`): la URL canonica de un advisory OSV es una
    referencia visible para humanos reconstruida en codigo, no un destino de red (la
    red va a `api.osv.dev` via la allowlist efectiva del cliente). La prosa de
    docstrings se excluye a proposito. Funcion PURA: parsea el texto, sin red ni FS.
    """
    tree = ast.parse(source)
    doc_ids = _docstring_nodes(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in doc_ids:
            continue
        for raw_url in _URL_RE.findall(node.value):
            host = _safe_hostname(raw_url)
            if host is None or not _DNS_HOST_RE.match(host):
                continue
            if host not in allowlist:
                violations.append(host)
    return violations


def _safe_hostname(raw_url: str) -> str | None:
    """Host en minusculas de `raw_url`, o None si la URL es imparseable.

    `urlsplit` puede lanzar `ValueError` (p.ej. literal IPv6 sin cerrar); ese caso
    se degrada a None en vez de propagar, igual que hace el cliente HTTP real.
    """
    try:
        host = urlsplit(raw_url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


# --------------------------------------------------------------------------- #
# Fixtures: codigo fuente real cacheado una vez por sesion
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def source_files() -> list[Path]:
    """Rutas de los .py del paquete (debe haber un numero razonable)."""
    files = _iter_source_files()
    assert len(files) >= 20, "se esperaban >=20 modulos en src/slopguard; arbol incompleto"
    return files


@pytest.fixture(scope="session")
def source_texts(source_files: list[Path]) -> dict[Path, str]:
    """Mapa ruta->texto de cada modulo, leido una sola vez."""
    return {path: path.read_text(encoding="utf-8") for path in source_files}


# --------------------------------------------------------------------------- #
# GUARDIA 1 - Pruebas sobre el codigo REAL
# --------------------------------------------------------------------------- #


def test_core_sin_exec_ni_import_dinamico_de_paquetes(source_texts: dict[Path, str]) -> None:
    """NFR-Seg.1: ningun modulo usa eval/exec/__import__ ni import dinamico.

    Arrange: textos reales del paquete. Act: corre el analizador por modulo.
    Assert: cero violaciones agregadas (con la ruta culpable si las hubiera).
    """
    offending: dict[str, list[str]] = {}
    for path, text in source_texts.items():
        found = find_dynamic_exec_violations(text)
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"import dinamico/ejecucion detectado (NFR-Seg.1): {offending}"


def test_guard1_detecta_violacion_plantada() -> None:
    """ANTI-VACUIDAD G1: el analizador MUERDE ante eval/exec/import dinamico.

    Si esta prueba pasara con un analizador roto (que nunca detecta), el guardia
    seria vacuo. Aqui se plantan 4 violaciones distintas y se exige deteccion;
    ademas se confirma que un snippet limpio (incl. import_module con literal) NO
    genera falsos positivos.
    """
    eval_snippet = "x = eval(user_name)\n"
    exec_snippet = "exec(manifest_code)\n"
    dunder_snippet = "mod = __import__(pkg_from_manifest)\n"
    dynamic_importlib = "import importlib\nm = importlib.import_module(dep_name)\n"

    assert find_dynamic_exec_violations(eval_snippet), "no detecto eval() plantado"
    assert find_dynamic_exec_violations(exec_snippet), "no detecto exec() plantado"
    assert find_dynamic_exec_violations(dunder_snippet), "no detecto __import__() plantado"
    assert find_dynamic_exec_violations(dynamic_importlib), "no detecto import_module(var)"

    # Falsos positivos: stdlib y un import_module con literal estatico son limpios.
    clean = "import json\nimport ast\nfrom typing import Final\nv = json.loads('{}')\n"
    assert find_dynamic_exec_violations(clean) == [], "falso positivo en codigo limpio"


# --------------------------------------------------------------------------- #
# GUARDIA 2 - Pruebas sobre el codigo REAL
# --------------------------------------------------------------------------- #


def test_solo_core_net_importa_modulos_de_red(source_texts: dict[Path, str]) -> None:
    """NFR-Priv.2: los modulos de red de stdlib solo se importan en core/net."""
    offending: dict[str, list[str]] = {}
    for path, text in source_texts.items():
        found = find_network_import_violations(text, in_core_net=_is_under_core_net(path))
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"import de red fuera de core/net (NFR-Priv.2): {offending}"


def test_sin_sdks_de_terceros_ni_llm(source_texts: dict[Path, str]) -> None:
    """NFR-Priv.2/Costo.1: ningun modulo importa SDK de tercero, LLM o pickle/marshal."""
    offending: dict[str, list[str]] = {}
    for path, text in source_texts.items():
        found = find_third_party_import_violations(text)
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"SDK de tercero/LLM/inseguro importado: {offending}"


def test_sin_urls_hardcodeadas_a_hosts_ajenos(source_texts: dict[Path, str]) -> None:
    """NFR-Priv.2: ninguna URL literal apunta a un host fuera del allowlist efectivo.

    Allowlist efectivo = `{pypi.org}` (transporte) + `{osv.dev}` (display): la URL
    canonica del advisory OSV (`https://osv.dev/vulnerability/<id>`) es una referencia
    de display reconstruida en `core/threatintel/osv.py`, no un destino de red. Cualquier
    OTRO host ajeno en un literal de codigo (incl. en osv.py) sigue siendo violacion.
    """
    offending: dict[str, list[str]] = {}
    for path, text in source_texts.items():
        found = find_foreign_url_hosts(text)
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"URL hardcodeada a host ajeno (NFR-Priv.2): {offending}"


def test_guard2_url_exime_display_osv_pero_muerde_otros() -> None:
    """ANTI-VACUIDAD G2c-bis: `osv.dev` (display) se exime; otro host de display NO.

    La exencion es ACOTADA a `osv.dev` (host canonico de la pagina del advisory que el
    codigo reconstruye), no una puerta abierta: un literal a cualquier otro host de
    'referencia' (p.ej. `cve.mitre.org`) se sigue detectando como violacion.
    """
    osv_display = 'BASE = "https://osv.dev/vulnerability/MAL-2025-1"\n'
    assert find_foreign_url_hosts(osv_display) == [], "osv.dev (display) no debe morder"

    other_display = 'REF = "https://cve.mitre.org/cgi-bin/cvename.cgi"\n'
    found = find_foreign_url_hosts(other_display)
    assert found == ["cve.mitre.org"], f"otro host de display debe morder: {found}"

    # El allowlist explicito SIN display sigue mordiendo osv.dev (la exencion es del default).
    strict = find_foreign_url_hosts(osv_display, allowlist=ALLOWLIST)
    assert "osv.dev" in strict, "con allowlist estricto osv.dev SI es violacion"


def test_allowlist_de_red_fijada_a_pypi_org(source_texts: dict[Path, str]) -> None:
    """NFR-Priv.2: la constante ALLOWED_HOSTS del cliente HTTP es exactamente {pypi.org}.

    Se extrae el valor por AST (no por import) del literal asignado a `ALLOWED_HOSTS`
    en core/net/http_client.py y se compara contra el allowlist canonico.
    """
    http_client = _SRC_PKG / "core" / "net" / "http_client.py"
    text = source_texts[http_client]
    hosts = _extract_allowed_hosts(text)
    assert hosts is not None, "no se hallo la asignacion de ALLOWED_HOSTS por AST"
    assert hosts == set(ALLOWLIST), f"allowlist de red != {{pypi.org}}: {hosts}"


def _extract_allowed_hosts(source: str) -> set[str] | None:
    """Conjunto de strings literales del valor de `ALLOWED_HOSTS`, o None si no aparece.

    Acepta `frozenset({...})`/`set({...})`/`{...}` y un set-literal directo; recorre
    los `Constant` string del nodo de valor. Funcion PURA (analiza el texto dado).
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        if not any(isinstance(t, ast.Name) and t.id == "ALLOWED_HOSTS" for t in targets):
            continue
        value = node.value
        if value is None:
            continue
        return {
            sub.value
            for sub in ast.walk(value)
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
        }
    return None


def test_guard2_red_detecta_import_de_red_fuera_de_net() -> None:
    """ANTI-VACUIDAD G2a: detecta un import de urllib/socket fuera de core/net."""
    foreign = "import socket\nimport urllib.request\n"
    # Fuera de core/net: debe morder ambos imports.
    found = find_network_import_violations(foreign, in_core_net=False)
    assert len(found) == 2, f"no detecto imports de red plantados: {found}"
    # Dentro de core/net: la frontera los permite (sin falsos positivos).
    assert find_network_import_violations(foreign, in_core_net=True) == []
    # Codigo sin red fuera de net: limpio.
    assert find_network_import_violations("import json\nimport ast\n", in_core_net=False) == []


def test_guard2_terceros_detecta_sdk_y_llm_plantados() -> None:
    """ANTI-VACUIDAD G2b: detecta requests/openai/pickle plantados; ignora stdlib."""
    assert find_third_party_import_violations("import requests\n"), "no detecto requests"
    assert find_third_party_import_violations("import openai\n"), "no detecto openai (LLM)"
    assert find_third_party_import_violations(
        "from anthropic import Anthropic\n"
    ), "no detecto anthropic (LLM)"
    assert find_third_party_import_violations("import pickle\n"), "no detecto pickle"
    # stdlib puro no debe disparar.
    assert find_third_party_import_violations("import json\nimport hashlib\n") == []


def test_guard2_url_detecta_host_ajeno_e_ignora_pypi_y_docstrings() -> None:
    """ANTI-VACUIDAD G2c: muerde un host ajeno literal; ignora pypi.org y docstrings.

    Cubre los falsos positivos reales del paquete: la prosa de docstrings con
    'http://,' o 'https://[fe80::1/x' NO debe contar como host ajeno.
    """
    evil = 'API = "https://evil.example.com/collect"\n'
    found = find_foreign_url_hosts(evil)
    assert found == ["evil.example.com"], f"no detecto host ajeno: {found}"

    # pypi.org (allowlist) en un literal real NO es violacion.
    allowed = 'BASE = "https://pypi.org/pypi/{name}/json"\n'
    assert find_foreign_url_hosts(allowed) == [], "falso positivo sobre pypi.org"

    # Prosa de docstring con basura tipo URL: se ignora (no es endpoint).
    docstring_noise = (
        '"""Ejemplos de prosa: http://, https://) y un IPv6 https://[fe80::1/x."""\n'
        "x = 1\n"
    )
    assert find_foreign_url_hosts(docstring_noise) == [], "falso positivo en docstring"

    # Un host ajeno DENTRO de un docstring se ignora por diseno (no es codigo de red);
    # pero el mismo host en un literal de codigo SI se detecta: demuestra la distincion.
    in_doc = '"""ver https://tracker.evil.net/x para detalles."""\nY = 2\n'
    assert find_foreign_url_hosts(in_doc) == [], "no debe escanear prosa de docstring"
    in_code = 'Y = "https://tracker.evil.net/x"\n'
    assert find_foreign_url_hosts(in_code), "debe detectar el mismo host en literal de codigo"


def test_guard2_allowlist_detecta_allowlist_adulterado() -> None:
    """ANTI-VACUIDAD G2d: el extractor de ALLOWED_HOSTS ve un host extra plantado."""
    tampered = 'ALLOWED_HOSTS = frozenset({"pypi.org", "evil.example.com"})\n'
    hosts = _extract_allowed_hosts(tampered)
    assert hosts == {"pypi.org", "evil.example.com"}, f"extraccion incorrecta: {hosts}"
    assert hosts != set(ALLOWLIST), "el adulterado deberia diferir del allowlist canonico"
    # Ausencia total de la constante => None (no un falso 'todo bien').
    assert _extract_allowed_hosts("X = 1\n") is None


# --------------------------------------------------------------------------- #
# GUARDIA 3 - Cero dependencias de runtime (NFR-Costo.1 / NFR-Mant.2)
# --------------------------------------------------------------------------- #


def _runtime_dependencies(pyproject_text: str) -> list[str]:
    """Lista `[project].dependencies` del TOML dado. Funcion PURA (parsea texto)."""
    data = tomllib.loads(pyproject_text)
    project = data.get("project", {})
    deps = project.get("dependencies", [])
    assert isinstance(deps, list), "[project].dependencies debe ser una lista TOML"
    return [str(d) for d in deps]


def test_cero_dependencias_de_runtime() -> None:
    """NFR-Costo.1/Mant.2: `[project].dependencies` esta vacio (solo stdlib)."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    deps = _runtime_dependencies(text)
    assert deps == [], f"se declararon dependencias de runtime (debe ser cero): {deps}"


def test_guard3_detecta_dependencia_plantada() -> None:
    """ANTI-VACUIDAD G3: el parser ve una dependencia plantada; lista vacia => limpio."""
    with_dep = '[project]\nname = "x"\nversion = "0"\ndependencies = ["requests>=2"]\n'
    assert _runtime_dependencies(with_dep) == ["requests>=2"], "no detecto la dep plantada"
    without = '[project]\nname = "x"\nversion = "0"\ndependencies = []\n'
    assert _runtime_dependencies(without) == [], "falso positivo sobre lista vacia"


# --------------------------------------------------------------------------- #
# GUARDIA 4 - Funciones <= 50 lineas (NFR-Mant.1)
# --------------------------------------------------------------------------- #

_MAX_FUNC_LINES = 50


def find_long_function_violations(source: str, filename: str = "<source>") -> list[str]:
    """Funciones con mas de _MAX_FUNC_LINES lineas. Vacia => limpio.

    Cuenta desde la linea `def`/`async def` hasta la ultima linea del cuerpo
    (ast.end_lineno) inclusive. Funcion PURA: opera sobre el texto recibido.
    """
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        end = node.end_lineno or node.lineno
        length = end - node.lineno + 1
        if length > _MAX_FUNC_LINES:
            violations.append(
                f"{node.name}() lineas {node.lineno}-{end} ({length} lineas > {_MAX_FUNC_LINES})"
            )
    return violations


def test_todas_las_funciones_menor_igual_50_lineas(source_texts: dict[Path, str]) -> None:
    """NFR-Mant.1: ninguna funcion del paquete supera 50 lineas.

    Arrange: textos reales del paquete. Act: analisis AST por modulo.
    Assert: cero funciones con longitud > 50 lineas.
    """
    offending: dict[str, list[str]] = {}
    for path, text in source_texts.items():
        found = find_long_function_violations(text, filename=str(path))
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"funciones > 50 lineas encontradas (NFR-Mant.1): {offending}"


def test_guard4_detecta_funcion_larga_plantada() -> None:
    """ANTI-VACUIDAD G4: el analizador muerde una funcion de 51 lineas plantada.

    Genera dinamicamente un snippet con una funcion de exactamente 51 lineas y
    confirma que se detecta; una funcion de exactamente 50 lineas no dispara.
    """
    # Funcion de 51 lineas: 'def f():\n' + 50 lineas de cuerpo = 51 totales.
    long_func = "def funcion_larga():\n" + "    x = 1\n" * 50
    found = find_long_function_violations(long_func)
    assert found, f"no detecto funcion de 51 lineas plantada: {found}"

    # Funcion de exactamente 50 lineas no debe disparar.
    ok_func = "def funcion_ok():\n" + "    x = 1\n" * 49
    assert find_long_function_violations(ok_func) == [], "falso positivo en funcion de 50 lineas"


# --------------------------------------------------------------------------- #
# GUARDIA 5 - Allowlist GENERALIZADA por-instancia (ADR-09, prop. estatica 4)
# --------------------------------------------------------------------------- #

# Cierre de hosts conocidos que CUALQUIER fuente de Capa 3 puede aportar al allowlist
# efectivo (ADR-09 invariante 2). El conjunto efectivo de cualquier instancia DEBE ser
# subconjunto de {base} | {estos}. Ni un host mas: un host fuera de aqui es una violacion.
_OSV_HOST: frozenset[str] = frozenset({"api.osv.dev"})
_WATCHLIST_HOST: frozenset[str] = frozenset({"depscope.dev"})
_LAYER3_KNOWN_HOSTS: frozenset[str] = _OSV_HOST | _WATCHLIST_HOST

# Allowlist EFECTIVO maximo concebible = base anclada + cierre de hosts de Capa 3.
_MAX_EFFECTIVE_ALLOWLIST: frozenset[str] = ALLOWLIST | _LAYER3_KNOWN_HOSTS


def _effective_allowlist(config: Config) -> frozenset[str]:
    """Conjunto EFECTIVO de hosts de la fuente compuesta real para `config`.

    Construye la fuente via el registry (camino de produccion) y devuelve
    `ALLOWED_HOSTS (base) | source.extra_allowed_hosts`. Si la Capa 3 esta apagada
    (`source is None`), el efectivo es solo la base anclada. No toca la red: solo
    instancia objetos y lee atributos. Funcion auxiliar (no analizador AST).
    """
    source = get_threatintel_source(config, use_cache=False)
    extra = frozenset() if source is None else source.extra_allowed_hosts
    return ALLOWLIST | extra


def test_g5_base_anclada_a_pypi_org() -> None:
    """ADR-09 invariante 1: `ALLOWED_HOSTS` base == {pypi.org}, sin contaminar de Capa 3.

    El espejo del test (`hc.ALLOWED_HOSTS`) y la constante canonica local coinciden y
    valen exactamente {pypi.org}: ningun host de Capa 3 se filtro a la base global.
    """
    assert hc.ALLOWED_HOSTS == frozenset({"pypi.org"}), "la base ALLOWED_HOSTS cambio"
    assert hc.ALLOWED_HOSTS == ALLOWLIST, "el espejo del test diverge de la base real"
    assert _LAYER3_KNOWN_HOSTS.isdisjoint(hc.ALLOWED_HOSTS), "host de Capa 3 en la base"


def test_g5_efectivo_por_instancia_subconjunto_del_cierre() -> None:
    """ADR-09 invariante 2: el efectivo de toda config valida ⊆ {pypi.org, osv, depscope}.

    Recorre las 4 combinaciones (enable_layer3 x enable_watchlist) y exige que el conjunto
    EFECTIVO de la fuente real nunca contenga un host fuera del cierre conocido. Ademas
    cada host efectivo debe ser un FQDN https seguro (no IP/localhost/puerto, anti-SSRF).
    """
    for enable_layer3 in (True, False):
        for enable_watchlist in (True, False):
            config = Config(enable_layer3=enable_layer3, enable_watchlist=enable_watchlist)
            effective = _effective_allowlist(config)
            assert effective <= _MAX_EFFECTIVE_ALLOWLIST, (
                f"efectivo fuera del cierre conocido: {effective}"
            )
            assert all(hc._is_valid_https_host(host) for host in effective), (
                f"host efectivo no es FQDN https seguro: {effective}"
            )


def test_g5_depscope_solo_con_watchlist_activa() -> None:
    """ADR-09 invariante 2 (R2.1): `depscope.dev` aparece SOLO con enable_watchlist=true.

    Con la watchlist apagada, la fuente no se instancia y su host nunca entra al efectivo
    (por construccion). Con la watchlist encendida (y Capa 3 activa), si entra. Si la Capa 3
    esta apagada, ni osv ni depscope aparecen (modo solo-deterministas, R5.3).
    """
    sin_wl = _effective_allowlist(Config(enable_layer3=True, enable_watchlist=False))
    assert sin_wl == frozenset({"pypi.org", "api.osv.dev"}), (
        "depscope.dev entro con watchlist apagada (R2.1)"
    )

    con_wl = _effective_allowlist(Config(enable_layer3=True, enable_watchlist=True))
    assert con_wl == frozenset({"pypi.org", "api.osv.dev", "depscope.dev"}), (
        "conjunto efectivo con watchlist activa difiere del esperado"
    )

    apagada = _effective_allowlist(Config(enable_layer3=False))
    assert apagada == ALLOWLIST, "Capa 3 apagada debe dejar solo la base {pypi.org}"


def _redirect_handler_of(client: SecureHttpClient) -> hc._RejectRedirectHandler:
    """Extrae el unico `_RejectRedirectHandler` cableado en el opener del cliente.

    `OpenerDirector.handlers` existe en runtime aunque los stubs de typeshed no lo expongan;
    se lee de forma defensiva con `getattr`. Falla si no hay exactamente un handler propio.
    """
    handlers = [
        handler
        for handler in getattr(client._opener, "handlers", [])
        if isinstance(handler, hc._RejectRedirectHandler)
    ]
    assert len(handlers) == 1, "debe haber exactamente un redirect handler propio"
    return handlers[0]


def test_g5_redirect_handler_valida_contra_efectivo_inyectado() -> None:
    """ADR-09 fix SSRF §3.3: el redirect handler valida contra el EFECTIVO de la instancia.

    El `SecureHttpClient` con `extra_allowed_hosts={api.osv.dev}` cablea su
    `_RejectRedirectHandler` con el conjunto efectivo {pypi.org, api.osv.dev}, NO la global.
    Se confirma estructuralmente (el handler porta el efectivo, igual que `client._allowed_hosts`)
    y por comportamiento (un destino fuera del efectivo da 'no permitido'; uno dentro da
    'inesperada': el handler NUNCA sigue una redireccion, solo cambia el mensaje).
    """
    client = SecureHttpClient(extra_allowed_hosts=_OSV_HOST)
    effective = ALLOWLIST | _OSV_HOST
    assert client._allowed_hosts == effective, "el efectivo de la instancia diverge"
    handler = _redirect_handler_of(client)
    assert handler._allowed_hosts == effective, (
        "el redirect handler no recibio el conjunto EFECTIVO de la instancia"
    )
    with pytest.raises(NetworkUnverifiableError, match="no permitido"):
        handler.redirect_request(None, None, 302, "F", None, "https://evil.example/x")  # type: ignore[arg-type]
    with pytest.raises(NetworkUnverifiableError, match="inesperada"):
        handler.redirect_request(None, None, 302, "F", None, "https://api.osv.dev/y")  # type: ignore[arg-type]


# Vectores SSRF del pentest (A10): cada uno debe ser RECHAZADO por el allowlist efectivo,
# nunca interpretado como uno de los hosts permitidos. Cubre IPs internas, metadata cloud,
# encodings de IP (decimal/hex/octal), IPv6, userinfo, puerto explicito.
_SSRF_HOST_VECTORS: tuple[str, ...] = (
    "127.0.0.1",  # loopback
    "10.0.0.5",  # privada 10/8
    "172.16.0.1",  # privada 172.16/12
    "192.168.1.1",  # privada 192.168/16
    "169.254.169.254",  # metadata cloud (AWS/GCP)
    "2130706433",  # 127.0.0.1 en decimal
    "0x7f000001",  # 127.0.0.1 en hex
    "0177.0.0.1",  # 127.0.0.1 en octal
    "[::1]",  # IPv6 loopback
    "[fd00::1]",  # IPv6 ULA privada
    "localhost",  # nombre interno
)


@pytest.mark.parametrize("host", _SSRF_HOST_VECTORS)
def test_g5_ssrf_vector_rechazado_por_allowlist_efectivo(host: str) -> None:
    """A10 SSRF: el efectivo maximo {pypi.org, osv, depscope} rechaza todo host interno.

    Aun con el allowlist MAS amplio posible (Capa 3 + watchlist), ninguno de los vectores
    de SSRF (loopback, privadas, metadata, encodings de IP, IPv6, userinfo via host crudo,
    localhost) pasa `_is_allowed`: la defensa es por inclusion estricta en el conjunto, no
    por parseo permisivo. Tambien `_is_valid_https_host` los rechaza (defensa en profundidad).
    """
    assert not hc._is_allowed("https", host, _MAX_EFFECTIVE_ALLOWLIST), (
        f"vector SSRF '{host}' fue ADMITIDO por el allowlist efectivo"
    )
    assert not hc._is_valid_https_host(host.strip("[]")), (
        f"vector SSRF '{host}' paso el predicado de FQDN https seguro"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@pypi.org/x",  # userinfo: el host crudo es pypi.org
        "https://pypi.org:8080/x",  # puerto explicito
        "https://attacker@api.osv.dev/x",  # userinfo sobre host permitido
    ],
)
def test_g5_ssrf_userinfo_y_puerto_rechazados_en_validacion(url: str) -> None:
    """A10 SSRF: userinfo y puerto explicito se rechazan en `_validate_url` aun con host OK.

    `urlsplit().hostname` descarta el `user@` y el `:puerto`, asi que una URL como
    `https://user:pass@pypi.org/x` pasaria la allowlist por el host desnudo. El cliente
    DEBE rechazarla antes de consultar el allowlist (defecto-deniega). Se prueba contra el
    efectivo real de una instancia con osv+depscope habilitados.
    """
    client = SecureHttpClient(extra_allowed_hosts=_LAYER3_KNOWN_HOSTS)
    with pytest.raises(NetworkUnverifiableError):
        client._validate_url(url)


def test_g5_redirect_chain_cross_host_siempre_rechazado() -> None:
    """A10 SSRF: ninguna redireccion se sigue, ni siquiera entre dos hosts del efectivo.

    Un `30x` de `api.osv.dev` a `pypi.org` (ambos en el efectivo) DEBE rechazarse: la
    politica es 'no se sigue ninguna redireccion', no 'solo cross-host'. Asi se cierra el
    redirect-chain cross-host como vector. Un destino http(s) ajeno tambien se rechaza.
    """
    handler = hc._RejectRedirectHandler(_MAX_EFFECTIVE_ALLOWLIST)
    # api.osv.dev -> pypi.org: ambos permitidos, pero la redireccion NO se sigue.
    with pytest.raises(NetworkUnverifiableError, match="inesperada"):
        handler.redirect_request(None, None, 302, "F", None, "https://pypi.org/redir")  # type: ignore[arg-type]
    # cross-scheme a un host permitido: rechazado por scheme.
    with pytest.raises(NetworkUnverifiableError, match="no permitido"):
        handler.redirect_request(None, None, 302, "F", None, "http://pypi.org/x")  # type: ignore[arg-type]
    # redirect a metadata cloud: rechazado por host.
    with pytest.raises(NetworkUnverifiableError, match="no permitido"):
        handler.redirect_request(None, None, 302, "F", None, "https://169.254.169.254/")  # type: ignore[arg-type]


def test_g5_detecta_allowlist_efectivo_adulterado_plantado() -> None:
    """ANTI-VACUIDAD G5: si el efectivo crece con un host fuera del cierre, el guardia muerde.

    Simula un efectivo adulterado (host de exfiltracion plantado) y exige que la invariante
    de subconjunto FALLE; ademas, un `_is_allowed` evaluado contra ese efectivo adulterado
    SI admitiria el host malicioso, demostrando el agujero que el guardia de subconjunto
    previene. El efectivo legitimo (sin plantar) sigue siendo subconjunto del cierre.
    """
    tampered = _MAX_EFFECTIVE_ALLOWLIST | frozenset({"exfil.attacker.net"})
    assert not (tampered <= _MAX_EFFECTIVE_ALLOWLIST), "el guardia de subconjunto no mordio"
    # Con el efectivo adulterado, el host de exfiltracion seria admitido: ese es el peligro.
    assert hc._is_allowed("https", "exfil.attacker.net", tampered), "el adulterado no admite?"
    # El efectivo legitimo de cualquier config sigue dentro del cierre (no es vacuo).
    legit = _effective_allowlist(Config(enable_layer3=True, enable_watchlist=True))
    assert legit <= _MAX_EFFECTIVE_ALLOWLIST, "el efectivo legitimo salio del cierre"


# --------------------------------------------------------------------------- #
# GUARDIA 6 - Aislamiento de Capa 3 (NFR-Seg.1/Seg.3/Priv.2)
# --------------------------------------------------------------------------- #

# Frontera de transporte: SOLO `core/net` puede CONSTRUIR un transporte de red. Una IMPL
# de Capa 3 que instanciara `urllib.request.urlopen`/`socket.socket`/etc. sortearia el
# `SecureHttpClient` (sin allowlist/TLS): es una violacion aunque no importe el modulo de
# red (p.ej. via un alias). Nombres de constructores de transporte crudo prohibidos.
_RAW_TRANSPORT_CALLS: frozenset[str] = frozenset(
    {"urlopen", "socket", "create_connection", "HTTPConnection", "HTTPSConnection"}
)


def _layer3_source_files() -> list[Path]:
    """.py del subconjunto de Capa 3: core/threatintel/* + core/layers/layer3_threatintel."""
    threatintel = (_SRC_PKG / "core" / "threatintel").rglob("*.py")
    layer3 = _SRC_PKG / "core" / "layers" / "layer3_threatintel.py"
    files = [p for p in threatintel if "__pycache__" not in p.parts]
    files.append(layer3)
    return sorted(files)


def find_raw_transport_violations(source: str) -> list[str]:
    """Construcciones de transporte de red crudo (sortean `SecureHttpClient`). Vacia => limpio.

    Detecta `Call` cuyo nombre simple (Name o Attribute) sea un constructor de transporte
    crudo (`urlopen`/`socket`/`create_connection`/`HTTP(S)Connection`). Una IMPL de Capa 3
    DEBE delegar toda la red en `core/net`; abrir un socket/urlopen propio violaria la
    frontera y la allowlist (NFR-Priv.2). Funcion PURA: opera sobre el texto recibido.
    """
    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_func_name(node.func)
        if name in _RAW_TRANSPORT_CALLS:
            violations.append(f"transporte de red crudo '{name}()' en linea {node.lineno}")
    return violations


@pytest.fixture(scope="session")
def layer3_texts() -> dict[Path, str]:
    """Mapa ruta->texto del subconjunto de modulos de Capa 3 (≥5 modulos esperados)."""
    files = _layer3_source_files()
    assert len(files) >= 5, f"arbol de Capa 3 incompleto: {[_rel(p) for p in files]}"
    return {path: path.read_text(encoding="utf-8") for path in files}


def test_g6_capa3_sin_exec_ni_import_de_paquetes_analizados(
    layer3_texts: dict[Path, str],
) -> None:
    """NFR-Seg.1/Seg.3: Capa 3 nunca ejecuta/importa el codigo de un paquete analizado.

    Reusa el analizador del Guardia 1 sobre el subconjunto de Capa 3: ni eval/exec/__import__
    ni import dinamico de importlib. Capa 3 solo inspecciona IDs de advisories y nombres.
    """
    offending: dict[str, list[str]] = {}
    for path, text in layer3_texts.items():
        found = find_dynamic_exec_violations(text)
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"Capa 3 ejecuta/importa codigo dinamico (NFR-Seg.1): {offending}"


def test_g6_capa3_sin_sdks_de_terceros_ni_llm(layer3_texts: dict[Path, str]) -> None:
    """NFR-Priv.2: ningun modulo de Capa 3 importa SDK de tercero, LLM ni pickle/marshal."""
    offending: dict[str, list[str]] = {}
    for path, text in layer3_texts.items():
        found = find_third_party_import_violations(text)
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"Capa 3 importa SDK/LLM/inseguro (NFR-Priv.2): {offending}"


def test_g6_layer3_puro_no_importa_red_ni_construye_transporte(
    layer3_texts: dict[Path, str],
) -> None:
    """NFR-Priv.2: solo las IMPLs usan `core/net`; `layer3_threatintel` ni eso, y nadie

    construye transporte crudo. La capa pura `layer3_threatintel` NO importa modulos de red
    de stdlib (recibe `ThreatIntelResult` inyectado); ninguna IMPL ni la capa abren un
    socket/urlopen propio (todo el transporte sale del `SecureHttpClient` de `core/net`).
    """
    layer3_pure = _SRC_PKG / "core" / "layers" / "layer3_threatintel.py"
    net_offending: dict[str, list[str]] = {}
    transport_offending: dict[str, list[str]] = {}
    for path, text in layer3_texts.items():
        # La capa PURA no debe importar red de stdlib (in_core_net=False); las IMPLs si pueden.
        if path == layer3_pure:
            net = find_network_import_violations(text, in_core_net=False)
            if net:
                net_offending[_rel(path)] = net
        # NADIE en Capa 3 construye transporte crudo: todo va por SecureHttpClient (core/net).
        raw = find_raw_transport_violations(text)
        if raw:
            transport_offending[_rel(path)] = raw
    assert net_offending == {}, f"layer3 puro importa red (NFR-Priv.2): {net_offending}"
    assert transport_offending == {}, f"Capa 3 abre transporte crudo: {transport_offending}"


def test_g6_capa3_sin_urls_a_hosts_ajenos(layer3_texts: dict[Path, str]) -> None:
    """NFR-Priv.2: ninguna URL literal de Capa 3 apunta fuera del allowlist efectivo.

    Allowlist efectivo del detector = {pypi.org} (transporte) + {osv.dev} (display de la
    pagina del advisory, reconstruida). Cualquier otro host literal en Capa 3 es violacion.
    """
    offending: dict[str, list[str]] = {}
    for path, text in layer3_texts.items():
        found = find_foreign_url_hosts(text)
        if found:
            offending[_rel(path)] = found
    assert offending == {}, f"Capa 3 con URL a host ajeno (NFR-Priv.2): {offending}"


def test_g6_detecta_transporte_crudo_plantado() -> None:
    """ANTI-VACUIDAD G6: el analizador muerde un urlopen/socket plantado; ignora limpio.

    Planta cuatro construcciones de transporte crudo (urlopen, socket.socket,
    create_connection, HTTPSConnection) y exige deteccion; un snippet que solo usa
    `SecureHttpClient` (sin abrir transporte propio) NO debe disparar falso positivo.
    """
    assert find_raw_transport_violations("r = urlopen(u)\n"), "no detecto urlopen plantado"
    assert find_raw_transport_violations("s = socket.socket()\n"), "no detecto socket plantado"
    assert find_raw_transport_violations(
        "c = socket.create_connection((h, 443))\n"
    ), "no detecto create_connection plantado"
    assert find_raw_transport_violations(
        "x = http.client.HTTPSConnection(h)\n"
    ), "no detecto HTTPSConnection plantado"
    # Delegar en el cliente endurecido (sin abrir transporte propio) es limpio.
    clean = "client = SecureHttpClient(extra_allowed_hosts=hosts)\nr = client.post_json(u, b)\n"
    assert find_raw_transport_violations(clean) == [], "falso positivo al usar SecureHttpClient"
