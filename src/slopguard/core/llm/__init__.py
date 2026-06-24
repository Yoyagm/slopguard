"""Modulo LLM de SlopGuard: abstraccion, adaptador Anthropic, prompt y cache (Hito 3, Capa 4).

Submodulos:
- ``prompt``    - construccion del prompt y esquema de salida estructurada.
- ``evaluator`` - Protocol ``LlmEvaluator`` (abstraccion).
- ``anthropic`` - implementacion HTTPS cruda con ``SecureHttpClient``.
- ``resolver``  - gating de banda gris, presupuesto y cache.
"""
