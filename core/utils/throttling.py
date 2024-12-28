"""My custom throttling classes"""
# pylint: disable=missing-class-docstring
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


# Anonymous throttles
#                   Requests per minute

class AnonMin3Throttle(AnonRateThrottle):
    scope = 'anon_min_3'


class AnonMin5Throttle(AnonRateThrottle):
    scope = 'anon_min_5'


class AnonMin10Throttle(AnonRateThrottle):
    scope = 'anon_min_10'


class AnonMin15Throttle(AnonRateThrottle):
    scope = 'anon_min_15'


#                   Requests per hour
class AnonHour10Throttle(AnonRateThrottle):
    scope = 'anon_hour_10'


class AnonHour15Throttle(AnonRateThrottle):
    scope = 'anon_hour_15'


class AnonHour30Throttle(AnonRateThrottle):
    scope = 'anon_hour_30'


#                   Requests per day
class AnonDay20Throttle(AnonRateThrottle):
    scope = 'anon_day_20'


# User throttles
#                   Requests per minute
class UserMin2Throttle(UserRateThrottle):
    scope = 'user_min_2'


class UserMin20Throttle(UserRateThrottle):
    scope = 'user_min_20'


#                   Requests per hour
class UserHour10Throttle(UserRateThrottle):
    scope = 'user_hour_10'


#                   Requests per day
class UserDay100Throttle(UserRateThrottle):
    scope = 'user_day_100'
