"""Django project utils."""
from rest_framework.views import exception_handler
from rest_framework.exceptions import ErrorDetail

from utils.error_handling import MyErrors
from utils.custom_logging import programmer_logger


def custom_exception_handler(exc, context):
    """Custom exception handler which:
    1.represent multi error messages individually.
    2.has field, detail, code in response data
    3.include error code for non_field_errors."""

    # Get the default response from DRF's exception handler
    response = exception_handler(exc, context)

    if response is not None:
        if response.status_code == 400:
            programmer_logger.debug(f'Errors through my custom exception handler: \n{response.data.items()}')

            # Dictionary to store each error under its field name
            formatted_errors = {}

            for field, errors in response.data.items():
                programmer_logger.debug(f'list -> {field}: {errors}')
                # If errors is a list, handle each error individually
                if isinstance(errors, list):

                    formatted_errors[field] = []
                    for error in errors:
                        formatted_errors[field].append({
                            'detail': error if isinstance(error, str) else error.get('message', ''),
                            'code': error.code if isinstance(error, ErrorDetail) and error.code else 'error'
                        })
                else:
                    # For single errors, add directly
                    programmer_logger.debug(f'single -> {field}: {errors}')
                    formatted_errors[field] = [{
                        'detail': errors if isinstance(errors, str) else errors.get('message', ''),
                        'code': getattr(exc, 'default_code', 'error')
                    }]

            # Wrap the formatted errors under 'errors' key
            response.data = {'errors': formatted_errors}

        elif response.status_code == 429:  # Too many requests
            programmer_logger.debug(f'Original response for 429 error is: {response.data}')
            response.data = {
                'code': MyErrors.TOO_MANY_REQUESTS['code'],
                'detail': MyErrors.TOO_MANY_REQUESTS['detail'],
                'retry_after': response.headers.get('Retry-After', 'Unknown')
            }

    return response
