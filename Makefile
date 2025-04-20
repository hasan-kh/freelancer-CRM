# Variables
LOCAL_APP_IMAGE_NAME=projectcrm
REGISTRY=$(CI_REGISTRY_IMAGE)
TAG=$(CI_COMMIT_REF_NAME)
DEPLOY_DIR_BASE=/home/hasan/projects/FreelancerCRM

# If CI_ENVIRONMENT_NAME is defined, force ENV to use it.
ifdef CI_ENVIRONMENT_NAME
  ENV := $(CI_ENVIRONMENT_NAME) # Set ENV if it's not already set also trim white spaces
else
  # Otherwise, use ENV if provided on the command line;
  # if not, default to "local".
  ENV ?= local
endif

# Example usages:
# make debug -> ENV=local
# make ENV=prod -> ENV=prod

STRIPPED_ENV = $(strip $(ENV))

# Define the appropriate Docker Compose file based on ENV
ifeq ($(STRIPPED_ENV),local)
  COMPOSE_FILES=-f docker-compose.yml -f docker-compose.override.yml
else ifeq ($(STRIPPED_ENV),dev)
  COMPOSE_FILES=-f docker-compose.yml -f docker-compose.dev.yml
else ifeq ($(STRIPPED_ENV),prod)
  COMPOSE_FILES=-f docker-compose.yml -f docker-compose.prod.yml
else
  $(error Invalid ENV value $(STRIPPED_ENV). Use 'local', 'dev', or 'prod'.)
endif

DOCKER_COMPOSE=docker compose $(COMPOSE_FILES)

debug:
	@echo "ENV: $(ENV)"
	@echo "STRIPPED ENV: $(STRIPPED_ENV)"
	@echo "DOCKER_COMPOSE: $(DOCKER_COMPOSE)"
	@echo "LOCAL_APP_IMAGE_NAME: $(LOCAL_APP_IMAGE_NAME)"
	@echo "REGISTRY(CI_REGISTRY_IMAGE): $(CI_REGISTRY_IMAGE)"
	@echo "TAG(CI_COMMIT_REF_NAME): $(CI_COMMIT_REF_NAME)"

# Log in container registry
login_registry:
	docker login -u $(CI_REGISTRY_USER) -p $(CI_REGISTRY_PASSWORD) $(CI_REGISTRY)

# Create env files from templates if not already present
create-env-files:
	@test -f ./envs/.env || cp ./envs/.env.tpl ./envs/.env
	@test -f ./envs/.env.db || cp ./envs/.env.db.tpl ./envs/.env.db
	@test -f ./envs/.env.rabbitmq || cp ./envs/.env.rabbitmq.tpl ./envs/.env.rabbitmq
	@test -f ./envs/.env.flower || cp ./envs/.env.flower.tpl ./envs/.env.flower
	@test -f ./envs/.env.proxy || cp ./envs/.env.proxy.tpl ./envs/.env.proxy

# Build the app image for local use
build-local:
	docker build -t $(LOCAL_APP_IMAGE_NAME):latest .

# Build for CI/CD
build-ci:
    # Build docker images, i use same image for app and celery services
	docker build -t $(REGISTRY)/app:$(TAG) .
	docker build -t $(REGISTRY)/flower:$(TAG) -f flower/Dockerfile .
	docker build -t $(REGISTRY)/proxy:$(TAG) proxy/

# Lint
lint-ci:
	$(DOCKER_COMPOSE) run --rm --no-deps app sh -c "cd /app && sh ./scripts/lint.sh"

# Test
test-ci:
	$(DOCKER_COMPOSE) run --rm app sh -c "sh /app/scripts/wait_for_rabbitmq.sh && \
										  sh /app/scripts/wait_for_redis.sh && \
									   	  cd core && \
									      python manage.py wait_for_db && \
									      python manage.py test"
	$(DOCKER_COMPOSE) down --remove-orphans

# Push images registry
push:
	docker push $(REGISTRY)/app:$(TAG)
	docker push $(REGISTRY)/flower:$(TAG)
	docker push $(REGISTRY)/proxy:$(TAG)

# Run services locally
up:
	$(DOCKER_COMPOSE) up -d

# Stop services and delete containers
down:
	$(DOCKER_COMPOSE) down --remove-orphans

# Pull latest images from registry
pull:
	$(DOCKER_COMPOSE) pull

cleanup:
	$(DOCKER_COMPOSE) down --remove-orphans

prepare-deployment-files:
	# Create deployment directory if needed
	@echo "Preparing deployment directory for $(STRIPPED_ENV)..."
	mkdir -p $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)

	# Copy docker compose files
	cp docker-compose.yml $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/

ifeq ($(STRIPPED_ENV),dev)
	cp docker-compose.dev.yml $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/
else ifeq ($(STRIPPED_ENV),prod)
	cp docker-compose.prod.yml $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/
endif

prepare-deployment-envs:
	@echo "Preparing environment files for $(STRIPPED_ENV)..."

	# Create a persistent env directory
	mkdir -p $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs

	# Copy the template files only if the final file does not exist already.
	@test -f $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env || cp envs/.env.tpl $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env
	@test -f $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.db || cp envs/.env.db.tpl $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.db
	@test -f $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.rabbitmq || cp envs/.env.rabbitmq.tpl $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.rabbitmq
	@test -f $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.flower || cp envs/.env.flower.tpl $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.flower
	@test -f $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.proxy || cp envs/.env.proxy.tpl $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV)/envs/.env.proxy


deploy:
	@echo "Deploying to $(STRIPPED_ENV) station..."
	$(MAKE) prepare-deployment-files
	$(MAKE) prepare-deployment-envs

	cd $(DEPLOY_DIR_BASE)/$(STRIPPED_ENV) && \
		$(DOCKER_COMPOSE) pull; \
		$(DOCKER_COMPOSE) down --remove-orphans; \
		$(DOCKER_COMPOSE) up -d
