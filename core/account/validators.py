"""Validators for account app."""

from django.core.exceptions import ValidationError
from utils.error_handling import MyErrors


def validate_cellphone_length_startswith(cellphone: str) -> None:
    """
    Validate cellphone has 11 digits length and starts with 09 digits.
    :param cellphone: cellphone number as string.
    :return: None
    """

    if (not cellphone.isdigit()) or (len(cellphone) != 11) or \
            (not cellphone.startswith('09')):
        raise ValidationError(
            MyErrors.INVALID_CELLPHONE['detail'],
            MyErrors.INVALID_CELLPHONE['code'],
        )
