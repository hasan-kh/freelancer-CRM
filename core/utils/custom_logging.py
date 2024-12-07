"""Custom logging utilities."""
import logging
from logging import Filter

from colorlog import ColoredFormatter

from utils.functions import get_ip_from_request


class IncludeClientColorFormatter(ColoredFormatter):
    """My custom color formatter which set client_ip and user_id to N/A
    if they are not provided."""
    def format(self, record):
        # Add custom attributes (client_ip, user_id) to the record
        if not hasattr(record, 'client_ip'):
            record.client_ip = 'N/A'
        if not hasattr(record, 'user_id'):
            record.user_id = 'N/A'

        return super().format(record)


class RequestFilter(Filter):
    """Request filter which provides client_ip and user_id for log message."""
    def filter(self, record):
        # Assume `record.request` is passed explicitly in logging calls
        request = getattr(record, 'request', None)
        if request:
            record.user_id = request.user.id if request.user.is_authenticated else "Anonymous"
            record.client_ip = get_ip_from_request(request)
        else:
            record.user_id = "N/A"
            record.client_ip = "N/A"
        return True


# Loggers to use across the project
user_action_logger = logging.getLogger('user_action')
programmer_logger = logging.getLogger('programmer')
