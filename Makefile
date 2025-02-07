# Variables
LOCAL_APP_IMAGE_NAME=my-app
REGISTRY=${CI_REGISTRY_IMAGE}
TAG=${CI_COMMIT_REF_NAME}
DOCKER_COMPOSE=docker compose -f docker-compose.yml

# Log in container registry
#login_registry:
#	docker login -u ${CI_REGISTRY_USER} -p $CI_REGISTRY_PASSWORD $CI_REGISTRY


# Build the app image for local use
build-local:
	docker build -t ${LOCAL_APP_IMAGE_NAME}:latest .

# Build for CI/CD
build-ci:
	# Create env files from templates
	cp ./envs/.env.tpl ./envs/.env
	cp ./envs/.env.db.tpl ./envs/.env.db
	cp ./envs/.env.rabbitmq.tpl ./envs/.env.rabbitmq
	cp ./envs/.env.flower.tpl ./envs/.env.flower

    # Build docker images, i use same image for app and celery services so i build only once
	docker build -t ${REGISTRY}/app:${TAG} .
	docker build -t ${REGISTRY}/flower:${TAG} -f flower/Dockerfile .

# Push images registry
push:
	docker push ${REGISTRY}/app:${TAG}
	docker push ${REGISTRY}/flower:${TAG}

# Run services locally
up:
	${DOCKER_COMPOSE} up -d

# Stop services and delete containers
down:
	${DOCKER_COMPOSE} down --remove-orphans

# Pull latest images from registry
pull:
	docker compose pull

deploy:
	${DOCKER_COMPOSE} pull
	${DOCKER_COMPOSE} down --remove-orphans
	${DOCKER_COMPOSE} up -d
