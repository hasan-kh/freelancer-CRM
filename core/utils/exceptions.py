"""Django project utils."""
from rest_framework.views import exception_handler
from rest_framework.exceptions import ErrorDetail


def custom_exception_handler(exc, context):
    """Custom exception handler which:
    1.represent multi error messages individually.
    2.has field, detail, code in response data
    3.include error code for non_field_errors."""

    # Get the default response from DRF's exception handler
    response = exception_handler(exc, context)

    if response is not None:
        # Dictionary to store each error under its field name
        formatted_errors = {}

        for field, errors in response.data.items():
            # If errors is a list, handle each error individually
            if isinstance(errors, list):
                if len(errors) == 1:
                    error = errors[0]
                    formatted_errors[field] = {
                        'detail': error if isinstance(error, str) else error.get('message', ''),
                        'code': error.code if isinstance(error, ErrorDetail) and error.code else 'error'
                    }
                else:
                    formatted_errors[field] = []
                    for error in errors:
                        formatted_errors[field].append({
                            'detail': error if isinstance(error, str) else error.get('message', ''),
                            'code': error.code if isinstance(error, ErrorDetail) and error.code else 'error'
                        })
            else:
                # For single errors, add directly
                formatted_errors[field] = {
                    'detail': errors if isinstance(errors, str) else errors.get('message', ''),
                    'code': getattr(exc, 'default_code', 'error')
                }

        # Wrap the formatted errors under 'errors' key
        response.data = {'errors': formatted_errors}

    return response

# from rest_framework.views import exception_handler
# from rest_framework.exceptions import ErrorDetail, ValidationError
# from core.error_handling import ErrorCodes, ValidationDetails
#
#
# def custom_exception_handler(exc, context):
#     # Call DRF's default exception handler first
#     response = exception_handler(exc, context)
#
#     if response is not None:
#         # Initialize the container for formatted errors
#         formatted_errors = {}
#
#         # Check if the exception is a ValidationError (common for serializers)
#         if isinstance(exc, ValidationError):
#             for field, messages in response.data.items():
#                 if isinstance(messages, list):
#                     formatted_errors[field] = []
#                     for message in messages:
#                         # Determine if the message is a DRF ErrorDetail or a plain string
#                         if isinstance(message, ErrorDetail):
#                             # DRF ErrorDetail (with a code attribute)
#                             formatted_errors[field].append({
#                                 'detail': message.args[0],  # Get the message string
#                                 'code': message.code if message.code else 'error'
#                             })
#                         else:
#                             # If it's a plain string (no ErrorDetail)
#                             error_info = get_error_info(message)
#                             if error_info:
#                                 formatted_errors[field].append(error_info)
#                             else:
#                                 # Fallback to custom error code if no match found
#                                 formatted_errors[field].append({
#                                     'detail': message,
#                                     'code': f'{field}_unknown_error'
#                                 })
#                 else:
#                     # Single message for a field
#                     if isinstance(messages, ErrorDetail):
#                         formatted_errors[field] = [{
#                             'detail': messages.args[0],
#                             'code': messages.code if messages.code else 'error'
#                         }]
#                     else:
#                         error_info = get_error_info(messages)
#                         if error_info:
#                             formatted_errors[field] = [error_info]
#                         else:
#                             formatted_errors[field] = [{
#                                 'detail': messages,
#                                 'code': f'{field}_unknown_error'
#                             }]
#
#         # If non-field errors are present, process them similarly
#         if 'non_field_errors' in response.data:
#             formatted_errors['non_field_errors'] = []
#             for message in response.data['non_field_errors']:
#                 if isinstance(message, ErrorDetail):
#                     formatted_errors['non_field_errors'].append({
#                         'detail': message.args[0],
#                         'code': message.code if message.code else 'error'
#                     })
#                 else:
#                     error_info = get_error_info(message)
#                     if error_info:
#                         formatted_errors['non_field_errors'].append(error_info)
#                     else:
#                         formatted_errors['non_field_errors'].append({
#                             'detail': message,
#                             'code': 'non_field_error_unknown'
#                         })
#
#         # Now set the response to our structured error format
#         response.data = {'errors': formatted_errors}
#
#     return response
#
#
# def get_error_info(message):
#     """
#     This function looks up the error code and message detail from predefined constants
#     and returns the structured error info.
#     """
#     # Check for matching error message in ValidationDetails
#     for error_code, validation_message in ValidationDetails.__dict__.items():
#         if not error_code.startswith("__"):  # Skip magic methods
#             if validation_message.lower() == message.lower():
#                 # Return the matching error code and message
#                 return {
#                     'detail': validation_message,
#                     'code': getattr(ErrorCodes, error_code)
#                 }
#
#     # If no match found, return None
#     return None
