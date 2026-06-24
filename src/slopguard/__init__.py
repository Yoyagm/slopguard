"""SlopGuard: guardian pre-instalacion contra slopsquatting.

Escanea las dependencias Python de un proyecto y detecta paquetes inexistentes
(alucinados por LLMs), typosquatting o de metadatos sospechosos ANTES de
instalarlos. Capas 0-2 deterministas, sin LLM ni red distinta de la PyPI JSON API.

Este paquete raiz solo expone la version. La API publica del dominio vive en
`slopguard.core`; la CLI en `slopguard.cli`.
"""

__version__ = "0.3.0"

__all__ = ["__version__"]
