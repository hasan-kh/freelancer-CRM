DEBUG=0
SECRET_KEY=changeme
ALLOWED_HOSTS=127.0.0.1,localhost
JWT_SIGNING_KEY=changeme

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
