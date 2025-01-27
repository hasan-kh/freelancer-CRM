export DJANGO_SETTINGS_MODULE="core.settings"

echo "Running Flake8..."
flake8 --config=./scripts/.flake8 core

echo "Running Pylint..."
pylint --rcfile=./scripts/.pylintrc --recursive y -v core
