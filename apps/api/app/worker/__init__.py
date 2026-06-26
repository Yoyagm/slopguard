"""Escaneo asíncrono de PRs (Ola 5): cola de jobs, worker y publicación del Check Run.

El webhook (`app/api/webhooks.py`) solo ENCOLA tras verificar el HMAC y hace ack 202 (R9.3);
el trabajo pesado vive aquí, fuera del ciclo de request (ADR-2). La lógica del worker
(`pr_scan.process_pr_scan`) es una función pura inyectable, testeable sin Redis/Arq.
"""
