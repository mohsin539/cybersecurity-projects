"""Celery application configuration.

In production the browser-driving worker runs as a *separate* container so a
compromised lab page cannot influence the control-plane (least privilege,
ISO 27001 A.9.4 / NIST SC-7).
"""

from __future__ import annotations

from celery import Celery
from celery.signals import worker_process_init

from app.config import settings

celery_app = Celery(
    "xtester",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,                      # at-least-once: no lost scans
    task_reject_on_worker_lost=False,
    task_time_limit=60 * 30,                  # hard cap: 30 min
    task_soft_time_limit=60 * 25,
    broker_connection_retry_on_startup=True,
    result_expires=86400,
)


@worker_process_init.connect
def _init_worker(**_) -> None:
    # Fresh registry per worker process to avoid cross-scan contamination.
    from app.engine.detection import memory_registry

    memory_registry.clear()