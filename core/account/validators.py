"""Validators for account app."""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


def validate_cellphone_length_startswith(cellphone: str) -> None:
    """
    Validate cellphone has 11 digits length and starts with 09 digits.
    :param cellphone: cellphone number as string.
    :return: None
    """

    if (not cellphone.isdigit()) or (len(cellphone) != 11) or \
            (not cellphone.startswith('09')):
        raise ValidationError(_('Cellphone must be 11 digits long and starts with 09'))
