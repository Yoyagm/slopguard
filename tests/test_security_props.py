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
                violations.append(f"URL a host ajeno '{host}' en linea {node.lineno}")
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
    assert found and "cve.mitre.org" in found[0], f"otro host de display debe morder: {found}"

    # El allowlist explicito SIN display sigue mordiendo osv.dev (la exencion es del default).
    strict = find_foreign_url_hosts(osv_display, allowlist=ALLOWLIST)
    assert strict and "osv.dev" in strict[0], "con allowlist estricto osv.dev SI es violacion"


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
    assert found and "evil.example.com" in found[0], f"no detecto host ajeno: {found}"

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
