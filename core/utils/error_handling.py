"""Error codes to be centralized."""
from typing import Dict

from django.utils.translation import gettext as _
from django.conf import settings
from django.test import TestCase

from rest_framework import serializers


class MyErrors:
    """My custom errors, which error contains detail and code keys."""

    PASSWORD_TOO_SHORT = {
        'detail': _('This password is too short. It must contain at least '
                    '{password_min_length} characters.').format(password_min_length=settings.PASSWORD_MIN_LENGTH),
        'code': 'password_too_short'
    }

    PASSWORDS_DO_NOT_MATCH = {
        'detail': _('Passwords do not match.'),
        'code': 'passwords_do_not_match'
    }

    PASSWORD_INCORRECT = {
        'detail': _('password is incorrect.'),
        'code': 'password_incorrect'
    }

    REQUIRED_FIELD = {
        'detail': _('This field is required.'),
        'code': 'required_field'
    }

    REQUIRED_FIELDS = {
        'detail': _('Fill all required fields.'),
        'code': 'required_fields'
    }

    USER_EMAIL_NOT_FOUND = {
        'detail': _('Account with email({email}) not found.'),
        'code': 'user_email_not_found'
    }

    USER_INACTIVE = {
        'detail': _('Action not allowed, user({email}) is inactive.'),
        'code': 'user_inactive'
    }

    CODE_EXPIRED = {
        'detail': _('Code is expired.'),
        'code': 'code_expired'
    }

    CODE_INVALID = {
        'detail': _('Code is invalid.'),
        'code': 'code_invalid'
    }

    INVALID_CELLPHONE = {
        'detail': _('Cellphone must be 11 digits long and starts with 09.'),
        'code': 'invalid_cellphone'
    }

    BLANK = {
        'detail': _('This field may not be blank.'),
        'code': 'blank'
    }

    INCORRECT_CREDENTIALS = {
        'detail': _('Incorrect authentication credentials.'),
        'code': 'incorrect_credentials'
    }


# Error serializers
class FieldErrorDetailSerializer(serializers.Serializer):
    """Serializing detail of an error related to a field or non_filed_error."""
    detail = serializers.CharField()
    code = serializers.CharField()


class ErrorResponseSerializer(serializers.Serializer):
    """Serializing all errors in a dict, each field error can contain one or more FieldErrorDetail."""
    errors = serializers.DictField(child=FieldErrorDetailSerializer(many=True))


# Error handling functions
def get_error_response(response_data: dict, field_name: str) -> Dict[str, str]:
    """
    :param response_data: response of HTTP request
    :param field_name: field name like: username, non_field_error
    :return: Dict with keys: detail and code
    """
    error = response_data['errors'][field_name][0]
    return {'detail': error['detail'], 'code': error['code']}


def assert_expected_error_in_response_data(test_case_object: TestCase, response_data: dict, field_name: str,
                                           expected_error: dict, expected_error_context: dict = None) -> None:
    """
    Assert that the response contains the expected error detail and code for a specific field.
    :param test_case_object: Test case that this method runs in
    :param response_data: The response data from the HTTP request
    :param field_name: The field name (e.g. 'username', 'non_field_error')
    :param expected_error: The expected error dictionary containing 'detail' and 'code'
    :param expected_error_context: Context for expected_error['detail'] variables placeholder.
    :return: None
    """
    errors = response_data.get('errors', {})
    field_errors = errors.get(field_name, [])

    # Check if there is errors for specified fields
    if not field_errors:
        raise AssertionError(f'No errors found for field: {field_name}, errors are: {errors}')

    # Replace expected_error['detail'] variable placeholders with actual values if needed
    if expected_error_context:

        expected_error = {
            'detail': expected_error['detail'].format(**expected_error_context),
            'code': expected_error['code']
        }

    test_case_object.assertIn(expected_error, field_errors)


def assert_expected_error_code_in_response_data(test_case_object: TestCase, response_data: dict, field_name: str,
                                                expected_error_code: str) -> None:
    """
    Assert that the response contains the expected error code for a specific field.
    :param test_case_object: Test case that this method runs in
    :param response_data: The response data from the HTTP request
    :param field_name: The field name (e.g. 'username', 'non_field_error')
    :param expected_error_code: The expected error 'code'
    :return: None
    """
    errors = response_data.get('errors', {})
    field_errors = errors.get(field_name, [])

    # Check if there is errors for specified fields
    if not field_errors:
        raise AssertionError(f'No errors found for field: {field_name}, errors are: {errors}')

    # Extract error codes
    error_codes = [error.get('code') for error in field_errors]

    test_case_object.assertIn(expected_error_code, error_codes)
