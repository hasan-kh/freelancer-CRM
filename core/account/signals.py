"""Signals for account app."""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

from utils.tasks import task_create_otp_email_device_for_staff
from utils.custom_logging import programmer_logger


@receiver(post_save, sender=get_user_model())
def create_email_otp_device_for_staff(sender, instance, **kwargs):  # pylint: disable=unused-argument
    """
    If a user created as staff or updated to staff, create an email otp device for user.
    email OTP device is created so staff user enter admin panel via token that was sent via email,
    then she can add TOTP device for herself.
    """
    if instance.is_staff:
        programmer_logger.debug(f'User model post save signal: user created or updated as staff({instance})')
        task_create_otp_email_device_for_staff(user=instance)
