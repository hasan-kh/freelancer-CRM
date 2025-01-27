REDIS_HOST="redis"  # Replace with the Redis hostname or container name
REDIS_PORT=6379  # Redis default port

echo "Waiting for Redis server to start on $REDIS_HOST:$REDIS_PORT..."

while ! nc -z "$REDIS_HOST" "$REDIS_PORT"; do
  echo "Redis is not available yet. Retrying in 2 seconds... "
  sleep 2
done

echo "Redis server available!"
