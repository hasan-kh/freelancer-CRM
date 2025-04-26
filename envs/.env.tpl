DEBUG=0
SECRET_KEY=changeme
ALLOWED_HOSTS=127.0.0.1,localhost
JWT_SIGNING_KEY=changeme
TIME_ZONE=Asia/Tehran

DB_HOST=db
DB_PORT=5432
DB_NAME=dbname
DB_USER=dbuser
DB_PASSWORD=changeme

EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=example@gmail.com
EMAIL_HOST_PASSWORD=changeme
DEFAULT_FROM_EMAIL='Example website <example@gmail.com>'

PASSWORD_RESET_CODE_LENGTH=6
PASSWORD_RESET_CODE_EXPIRE_MINUTES=10

ADMINS=admin:admin@example.com,full name:manger@example.com

ADMIN_SITE_HEADER='Django Admin'
ADMIN_INDEX_TITLE=Administration
ADMIN_SITE_TITLE='Django Admin'

PROJECT_TITLE='Example Project'
# This will use in spectacular doc page header
PROJECT_DESCRIPTION='This is a brief description about project.'


# Activate OTP(One Time Password) for staff log in to admin, 1 for active, 0 for inactive
OTP_STAFF_ACTIVE=0
# The maximum number of seconds a token is valid.
OTP_EMAIL_TOKEN_VALIDITY=300
OTP_TOTP_ISSUER=website_name

# Redis
# redis location/URL protocol://IP:PORT/DATABASE
CACHE_REDIS_LOCATION=redis://redis:6379/0
# Optional: Prefix for all cache keys, all lower, without white space
REDIS_KEY_PREFIX=myapp

# Celery
CELERY_BROKER_URL='amqp://guest:guest@rabbitmq:5672/myvhost'
CELERY_RESULT_BACKEND=redis://redis:6379/1
