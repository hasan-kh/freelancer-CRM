"""My functions."""
from django.contrib.auth import get_user_model
from rest_framework.request import Request


def get_ip_from_request(request: Request) -> str:
    """Get the IP address from the request object."""
    # Extract client IP address from headers
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR', 'N/A')


def get_sentinel_user():
    """Sentinel user for deleted user relation."""
    sentinel_user = get_user_model().objects.get_or_create(email='deleted@example.com',
                                                           defaults={'is_active': False})[0]
    return sentinel_user
