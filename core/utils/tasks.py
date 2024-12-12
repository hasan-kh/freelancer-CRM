"""Tasks module for celery."""
import socket
from smtplib import SMTPException, SMTPRecipientsRefused, SMTPSenderRefused, SMTPDataError

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.sites.models import Site
from django.conf import settings

from utils.custom_logging import programmer_logger
from utils.email_defaults import (
    CHANGE_PASSWORD_EMAIL,
    PASSWORD_RESET_REQUEST_EMAIL,
)


def task_send_email_multi_alternatives(subject: str, message: str, recipient_email: str,
                                       html_template: str, html_context: dict) -> None:
    """
    Send an email with message as plain text version body, and
    attach text/html alternative using html_template and html_context.
    :param subject: Email subject
    :param message: Email Plain text body
    :param recipient_email: single recipient email address
    :param html_template: path to html template
    :param html_context: context to pass to html template
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

    try:
        email = EmailMultiAlternatives(

            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient_email]
        )
        email.attach_alternative(content=html_content, mimetype="text/html")
        email.send()
        programmer_logger.info(f'Email sent successfully to {recipient_email}.')

    except SMTPRecipientsRefused as e:
        programmer_logger.warning(f'Recipient email({recipient_email}) was refused by the server: {e}')
    except SMTPSenderRefused as e:
        programmer_logger.error(f'The email sender address was refused by the server: {e}')
    except SMTPDataError as e:
        programmer_logger.error(f'There was an issue with email message data\nmessage:{message}\nerror:{e}')
    except SMTPException as e:
        programmer_logger.error(f'An SMTP error occurred: {e}')
    except socket.timeout as e:
        programmer_logger.error(f'The connection to the SMTP server timed out: {e}')
    # Since I might forget to include an exception
    except Exception as e:  # pylint: disable=broad-exception-caught
        programmer_logger.error(f'An unexpected error occurred when sending email: {e}')


def task_change_password_mail(user_email):
    """Inform user via email when password changed successfully."""
    message = CHANGE_PASSWORD_EMAIL['message'] % {'user_email': user_email}

    task_send_email_multi_alternatives(
        subject=CHANGE_PASSWORD_EMAIL['subject'],
        message=message,
        recipient_email=user_email,
        html_template='email/inform.html',
        html_context={'message': message}
    )


def task_password_reset_request_mail(user_email: str, password_reset_code: str) -> None:
    """
    Send password reset code to user
    :param user_email: string
    :param password_reset_code: password reset code number as string
    """
    message = PASSWORD_RESET_REQUEST_EMAIL['message'] % {'user_email': user_email,
                                                         'password_reset_code': password_reset_code}

    task_send_email_multi_alternatives(
        subject=PASSWORD_RESET_REQUEST_EMAIL['subject'],
        message=message,
        recipient_email=user_email,
        html_template='email/password_reset_request.html',
        html_context={
            'user_email': user_email,
            'password_reset_code': password_reset_code}
    )
