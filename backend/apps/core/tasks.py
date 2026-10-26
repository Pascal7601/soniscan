"""Queue dispatch helper.

Lower layers (scans, domains) must not import the app that implements a task, so they enqueue by
task NAME. The message is sent only after the surrounding transaction commits, so a worker can
never receive a job for a row that does not exist yet.

If the broker is unreachable at that moment the row stays committed but the job is lost; the
`runner.reap_stale_scans` safety net fails scans that never started, and the user can retry.
"""

import logging

from celery import current_app
from django.db import transaction

logger = logging.getLogger(__name__)


def dispatch_on_commit(task_name: str, *args: str) -> None:
    def send() -> None:
        try:
            current_app.send_task(task_name, args=list(args))
        except Exception:
            logger.exception("could not enqueue %s", task_name)

    transaction.on_commit(send)