"""Error codes to be centralized."""
from django.utils.translation import gettext as _
from django.conf import settings


class ErrorCodes:
    """Custom error codes."""
    PASSWORD_TOO_SHORT = 'password_too_short'
    PASSWORDS_DO_NOT_MATCH = 'passwords_do_not_match'
    PASSWORD_INCORRECT = 'password_incorrect'
    REQUIRED_FIELD = 'required_field'
    REQUIRED_FIELDS = 'required_fields'

    BLANK = 'blank'


class ValidationDetails:
    """Custom validation details."""
    PASSWORD_TOO_SHORT = _('This password is too short. It must contain at least '
                           '%(password_min_length)d characters.') % ({'password_min_length':
                                                                      settings.PASSWORD_MIN_LENGTH})
    PASSWORDS_DO_NOT_MATCH = _('New passwords do not match.')
    PASSWORD_INCORRECT = _('password is incorrect.')
    REQUIRED_FIELD = _('This field is required.')
    REQUIRED_FIELDS = _('Fill all required fields.')

    BLANK = _('This field may not be blank.')
