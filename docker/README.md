# Docker + ngrok deployment

The Compose stack runs:

- `central-server` on the internal Docker network at port `5040`
- `ngrok`, forwarding the reserved HTTPS domain to `central-server:5040`
- `agent`, using the public ngrok HTTPS URL and persistent `/data` state

## Secrets

Copy `docker/ngrok.env.example` to the ignored root file `.env.ngrok` and replace every value. Never commit `.env.ngrok`.

## Start

```sh
docker compose --env-file .env.ngrok up -d --build
```

## Status and logs

```sh
docker compose --env-file .env.ngrok ps
docker compose --env-file .env.ngrok logs -f central-server ngrok agent
```

The ngrok inspection UI is local-only at `http://127.0.0.1:4040`.

## Stop

```sh
docker compose --env-file .env.ngrok down
```

Named volumes preserve the central SQLite database and agent identity/queue across container recreation. Add `-v` to `down` only when you intentionally want to delete that state.

## Scope warning

The containerized agent inventories its Linux container environment, not the Windows Docker host. The Docker socket mount allows the containers collector to inspect Docker metadata, subject to socket permissions. For host-level Windows posture, install the native Windows agent separately and point it at the same ngrok URL.
