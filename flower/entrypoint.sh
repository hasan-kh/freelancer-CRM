# Wait for rabbitmq service
sh ./scripts/wait_for_rabbitmq.sh

# Wait for redis service
sh ./scripts/wait_for_redis.sh

# create a celeryconfig.py file where i run celery flower command to set timezone for flower UI
# we use CELERY_TIMEZONE environment variable to set timezone
echo "Create celeryconfig.py in /app to set timezone using CELERY_TIMEZONE environment variable, flower UI uses this config file."
echo "timezone = '$CELERY_TIMEZONE'" > /app/celeryconfig.py

celery --broker="$CELERY_BROKER" flower --loglevel=DEBUG --port="$FLOWER_PORT"
