RABBITMQ_HOST="rabbitmq"  # Replace with the Rabbitmq hostname or container name
RABBITMQ_PORT=5672  # Rabbitmq default port

echo "Waiting for Rabbitmq server to start on $RABBITMQ_HOST:$RABBITMQ_PORT..."

while ! nc -z "$RABBITMQ_HOST" "$RABBITMQ_PORT"; do
  echo "Rabbitmq is not available yet. Retrying in 2 seconds... "
  sleep 2
done

echo "Rabbitmq server available!"
