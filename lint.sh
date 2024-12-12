#flake8 --ignore=E501 core && pylint --recursive y core
echo "Running Flake8..."
flake8 --config=.flake8 core

echo "Running Pylint..."
pylint --rcfile=.pylintrc --recursive y core
