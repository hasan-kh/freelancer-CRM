FROM python:3.13-alpine3.20
LABEL maintainer="hasan.kh9776@gmail.com"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY ./requirements.txt /tmp/
COPY ./core /app/core
COPY ./scripts /app/scripts

WORKDIR /app
EXPOSE 8000

RUN python -m venv /py && \
    /py/bin/pip install --upgrade pip && \
    apk add --update --no-cache postgresql-client && \
    apk add --update --no-cache --virtual .tmp-build-deps \
        build-base postgresql-dev musl-dev && \
    /py/bin/pip install -r /tmp/requirements.txt && \
    apk del .tmp-build-deps && \
    rm -rf /tmp && \
    adduser \
        --disabled-password \
        --no-create-home \
        django-user && \
    mkdir -p /vol/web/media && \
    mkdir -p /vol/web/static && \
    mkdir -p /app/core/logs && \
    chown -R django-user:django-user /vol && \
    chown -R django-user:django-user /app/core/logs && \
    chmod -R 755 /app/core/logs && \
    chmod -R 755 /vol

ENV PATH="/py/bin:$PATH"

USER django-user
