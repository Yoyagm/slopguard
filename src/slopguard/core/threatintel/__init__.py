"""Paquete threat-intel de SlopGuard.

Vacio de logica: no re-exporta las implementaciones concretas (osv, watchlist,
composite, resolver) para que la frontera de import-linter sea verificable
mecanicamente. El engine importa directamente desde los submodulos que necesita.
Ver design.md §1.3 (frontera R8.1/R8.3).
"""
