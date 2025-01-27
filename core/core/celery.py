"""Celery configuration."""
import os
from celery import Celery, Task
from celery.schedules import crontab
from kombu import Queue, Exchange
from django.conf import settings

from utils.custom_logging import programmer_logger


# Since celery worker container will not start server using manage.py or wsgi.py,
# we need to define DJANGO_SETTINGS_MODULE env variable here

# if not os.environ.get('DJANGO_SETTINGS_MODULE', False):
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
app = Celery('core')
app.config_from_object('django.conf:settings', namespace='CELERY')


app.conf.update(
    broker_url=settings.CELERY_BROKER_URL,
    result_backend=settings.CELERY_RESULT_BACKEND,
    timezone=settings.TIME_ZONE,  # Use Django's TIME_ZONE
    # if acks_late=True, task message is acknowledge only after the task is executed successfully,
    # Ensures tasks are not lost if a worker crashes mid-execution
    # For example when celery worker picks up a task from a queue (message broker) and it fails by worker,
    # the task will be lost forever (task_acks_late=False) but when we set task_acks_late=True
    # Then the task will not be acknowledged as picked up from queue as completed until it actually completes.
    task_acks_late=True,
    # When the worker lost connection from message broker any unacknowledged tasks from worker will be rejected
    # and assigned to the message broker to requeuing
    task_reject_on_worker_lost=True,
    task_default_priority=5,  # Default priority of tasks
    result_expires=3600,  # Task result expiration time in seconds
    accept_content=['json'],
    task_serializer='json',
    result_serializer='json',
)

# Queue settings
app.conf.task_queues = [
    Queue(
        'tasks',
        Exchange('tasks'),
        routing_key='tasks',
        queue_arguments={'x-max-priority': 10}),  # Enable priority (0-10)
]
app.conf.task_default_queue = 'tasks'  # Default queue name


app.conf.beat_schedule = {
    'task_flush_expired_tokens': {
        'task': 'utils.tasks.task_flush_expired_tokens',
        'schedule': crontab(minute='0'),  # Run every hour
    },
}


# Custom task class to handle failure
class CustomTask(Task):
    """Base class for all tasks with custom error handling."""

    def on_failure(self, exc, task_id,  # pylint: disable=too-many-arguments,too-many-positional-arguments
                   args, kwargs, einfo):
        """Error handler.
        This is run by the worker when the task fails.
        Arguments:
            exc (Exception): The exception raised by the task.
            task_id (str): Unique id of the failed task.
            args (Tuple): Original arguments for the task that failed.
            kwargs (Dict): Original keyword arguments for the task that failed.
            einfo (~billiard.einfo.ExceptionInfo): Exception information.

        Returns:
            None: The return value of this handler is ignored.
        """
        programmer_logger.error(f'Task {self.name} failed: {exc}. Args: {args}, Kwargs: {kwargs}, Info: {einfo}')


app.Task = CustomTask

# Auto discover tasks from all installed apps.
app.autodiscover_tasks()
