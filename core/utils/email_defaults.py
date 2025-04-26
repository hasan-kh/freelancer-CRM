"""Email defaults for different email types."""
from django.utils.translation import gettext as _

CHANGE_PASSWORD_EMAIL = {
    'subject': _('Your password has been changed.'),
    'message': _('Password for account({email}) has been changed.'),
}

PASSWORD_RESET_REQUEST_EMAIL = {
    'subject': _('Password reset'),
    'message': _('Use below code to reset password for account({email}).\n'
                 'Your code is: {password_reset_code}\n'
                 'If you did not make this request, Ignore it.'),
}
