"""Open api generic responses"""
from utils.error_handling import (
    Error400ResponseSerializer,
    Error401ResponseSerializer, ERROR401MESSAGES,
    Error429ResponseSerializer
)
from drf_spectacular.utils import OpenApiExample, OpenApiResponse


GenericOpenApiResponse400 = OpenApiResponse(
    description='Validation error occurred.Errors contain keys for '
    '`field name` (which means validation error raised for a certain field) or '
    '`non_field_errors` for errors that are not tied to a single field.',
    response=Error400ResponseSerializer,
)

GenericOpenApiResponse401 = OpenApiResponse(
    description='Not authorized: invalid, expired or black listed token or invalid authorization header.',
    response=Error401ResponseSerializer,
    examples=[
        OpenApiExample(
            name="Without Token",
            value=ERROR401MESSAGES['without_token'],
        ),
        OpenApiExample(
            name="Wrong Token Header",
            value=ERROR401MESSAGES['wrong_token_header'],
        ),
        OpenApiExample(
            name="Token Invalid or Expired",
            value=ERROR401MESSAGES['token_invalid_or_expired'],
        ),
        OpenApiExample(
            name="Token Blacklisted",
            value=ERROR401MESSAGES['token_blacklisted'],
        ),
    ]
)

GenericOpenApiResponse429 = OpenApiResponse(
    description='Too many requests',
    response=Error429ResponseSerializer,
)
