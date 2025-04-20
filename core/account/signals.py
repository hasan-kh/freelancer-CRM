"""Signals for account app."""

from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver
from django.apps import apps
from django.contrib.auth import get_user_model

from django_celery_beat.models import PeriodicTask, IntervalSchedule
from utils.tasks import task_create_otp_email_device_for_staff
from utils.custom_logging import programmer_logger


@receiver(post_save, sender=get_user_model())
def create_email_otp_device_for_staff(sender, instance, **kwargs):  # pylint: disable=unused-argument
    """
    If a user created as staff or updated to staff, create an email otp device for user.
    email OTP device is created so staff user enter admin panel via token that was sent via email,
    then she can add TOTP device for herself.
    """
    # Check if the user is staff
    if instance.is_staff:
        programmer_logger.debug(f'User model post save signal: user created or updated as staff({instance})')
        # Trigger the asynchronous task to create an OTP Email device for user
        task_create_otp_email_device_for_staff.delay(instance.id)


@receiver(post_migrate, sender=apps.get_app_config('account'))
def post_migrate_setup(sender, **kwargs):
    """Account app post migrate setup"""
    programmer_logger.debug(f'account post migrate signal - sender name: {sender.name}')

    programmer_logger.info('Starting post-migrate setup for "account" app.')

    # Create sentinel user
    sentinel_email = 'deleted@example.com'
    sentinel_defaults = {
        'is_active': False
    }
    sentinel_user, created = get_user_model().objects.get_or_create(email=sentinel_email,
                                                                    defaults=sentinel_defaults)
    if created:
        programmer_logger.info(f'sentinel_user created with email {sentinel_user} .')
    else:
        programmer_logger.info(f'sentinel_user with email {sentinel_user} already exists.')

    # Setup periodic tasks
    hour_interval_schedule, created = IntervalSchedule.objects.get_or_create(
        every=1,
        period=IntervalSchedule.HOURS,
    )

    if created:
        programmer_logger.info('hour_interval_schedule created.')
    else:
        programmer_logger.info('hour_interval_schedule already exists.')

    _, created = PeriodicTask.objects.update_or_create(
        name='Flush Expired Tokens',
        defaults={  # Use defaults to avoid missing required fields
            'interval': hour_interval_schedule,
            'task': 'utils.tasks.task_flush_expired_tokens',
            'enabled': True,  # Optional: Ensures the task is active
        },
    )

    if created:
        programmer_logger.info('"Flush Expired Tokens" Task created.')
    else:
        programmer_logger.info('"Flush Expired Tokens" Task updated.')
