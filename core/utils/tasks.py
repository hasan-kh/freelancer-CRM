"""Tasks module for celery."""
import socket
from smtplib import SMTPException

from django.core.mail import EmailMultiAlternatives
from django.core.management import call_command
from django.template.loader import render_to_string
from django.contrib.sites.models import Site
from django.conf import settings

from django_otp.plugins.otp_email.models import EmailDevice

from celery import shared_task

from utils.custom_logging import programmer_logger
from utils.email_defaults import (
    CHANGE_PASSWORD_EMAIL,
    PASSWORD_RESET_REQUEST_EMAIL,
)


@shared_task(queue='tasks', autoretry_for=(SMTPException, socket.timeout),
             max_retries=3, default_retry_delay=5)
def task_send_email_multi_alternatives(subject: str, message: str, recipient_email: str,
                                       html_template: str = None, html_context: dict = None) -> dict:
    """
    Send an email with message as plain text version body, and
    attach text/html alternative using html_template and html_context.
    :param subject: Email subject
    :param message: Email Plain text body
    :param recipient_email: single recipient email address
    :param html_template: path to html template (optional)
    :param html_context: context to pass to html template (optional)
    """
    # Get current site object
    current_site = Site.objects.get_current()

    # Add site domain and name to all html_context
    html_context.update({
        'site_domain': current_site.domain,
        'site_name': current_site.name
    })

    html_content = render_to_string(
        template_name=html_template,
        context=html_context,
    )

    email = EmailMultiAlternatives(

        subject=subject,
        body=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[recipient_email]
    )
    email.attach_alternative(content=html_content, mimetype="text/html")
    email.send()
    programmer_logger.info(f'Email sent successfully to {recipient_email}.')
    return {
        'subject': subject,
        'recipient_email': recipient_email,
    }


def send_change_password_mail(user_email: str) -> dict:
    """Inform user via email when password changed successfully."""
    message = CHANGE_PASSWORD_EMAIL['message'] % {'user_email': user_email}

    task_send_email_multi_alternatives.delay(
        subject=CHANGE_PASSWORD_EMAIL['subject'],
        message=message,
        recipient_email=user_email,
        html_template='email/inform.html',
        html_context={'message': message}
    )

    return {'user_email': user_email}


def send_password_reset_request_mail(user_email: str, password_reset_code: str) -> dict:
    """
    Send password reset code to user
    :param user_email: string
    :param password_reset_code: password reset code number as string
    """
    message = PASSWORD_RESET_REQUEST_EMAIL['message'] % {'user_email': user_email,
                                                         'password_reset_code': password_reset_code}

    task_send_email_multi_alternatives.delay(
        subject=PASSWORD_RESET_REQUEST_EMAIL['subject'],
        message=message,
        recipient_email=user_email,
        html_template='email/password_reset_request.html',
        html_context={
            'user_email': user_email,
            'password_reset_code': password_reset_code}
    )

    return {'user_email': user_email}


@shared_task(queue='tasks', bind=True, max_retries=3, default_retry_delay=5, priority=7)
def task_create_otp_email_device_for_staff(self, user_id: int,
                                           device_name: str = "Receive token via email") -> dict:
    """
    Create an OTP (One Time Password) email device for user.
    :param self: Celery task instance
    :param user_id: user id
    :param device_name: device name which shows up in admin login page
    :return: A dictionary containing user_id, email_device_id, created(boolean specifying whether
    an EmailDevice object was created or existed).
    """
    try:
        email_device, created = EmailDevice.objects.get_or_create(user_id=user_id, name=device_name)
        email_device_id = email_device.id
        programmer_logger.info(f'OTP email device object for staff({user_id}) creation status: {created} '
                               f'id: {email_device_id}')
        return {
            'user_id': user_id,
            'email_device_id': email_device_id,
            'created': created
        }
    except Exception as exc:  # pylint: disable=broad-exception-caught
        programmer_logger.error(f'An unexpected error occurred when creating OTP email device '
                                f'for staff({user_id}): {str(exc)}')
        raise self.retry(exc=exc)


# Scheduled Tasks
@shared_task(queue='tasks')
def task_flush_expired_tokens() -> None:
    """Run management command `flushexpiredtokens` which will
    delete any tokens from the outstanding list and blacklist that have expired."""

    # Call management command
    call_command('flushexpiredtokens', verbosity=2)
    programmer_logger.info('Task: flush_expired_tokens, expired tokens flushed successfully.')


# <editor-fold desc="shared_task all parameters doc">
# @shared_task(
#     name='example_task',  # A custom name for task, worker uses this name(opt)
#     bind=True,  # If true, the task instance will be past as first argument.
#                 # so first parameter of task function must be self(opt)
#     max_retries=5,  # Maximum number of retries
#     default_retry_delay=10,  # Delay in seconds before retrying a failed task
#     autoretry_for=(KeyError,),  # Tuple of exception classes for which the task should automatically retry
#     ignore_result=False,  # If true, the result of the task is not stored
#     serializer='json',  # Serializer format for task's arguments and result
#     acks_late=True,  # if true, task message is acknowledge only after the task is executed successfully,
#                      # Ensures tasks are not lost if a worker crashes mid-execution
#     rate_limit='5/s',  # Limit the rate of this task executions, exp: 10/m means only 10 per minute
#     priority=5  # Set priority of the task
#     options = {"time_limit": 60,  # Maximum runtime for the task in seconds before it's terminated
#                "soft_time_limit": 5},  # Grace period before the time limit,
#                                        # allows the task to handle timeout gracefully
#                                        # (exp: cleanup before termination)
#
# )
# </editor-fold>
