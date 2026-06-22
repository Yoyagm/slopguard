"""Fixtures y utilidades compartidas para la suite de SlopGuard.

Determinismo (NFR-Det.1): la edad de Capa 0 se deriva de un `now_epoch` inyectado
una sola vez por corrida. Los tests usan un epoch fijo en lugar del reloj real.
"""

from __future__ import annotations

# Epoch fijo para tests deterministas: 2024-06-01T00:00:00Z.
FROZEN_NOW_EPOCH: float = 1_717_200_000.0
