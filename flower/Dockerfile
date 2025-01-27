FROM mher/flower:latest
LABEL maintainer="hasan.kh9776@gmail.com"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to root to set ownership for the /app directory
USER root
COPY ./scripts /app/scripts
COPY ./flower/entrypoint.sh /app/entrypoint.sh
RUN chown -R flower:flower /app

# Switch back to the default user
USER flower

WORKDIR /app

EXPOSE 5555

CMD ["sh", "/app/entrypoint.sh"]
