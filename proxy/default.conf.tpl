server {
    listen ${LISTEN_PORT};

    location /static {
        alias /vol/static;
    }

    location / {
        proxy_pass http://${APP_HOST}:${APP_PORT};

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        client_max_body_size 10M;
    }
}
