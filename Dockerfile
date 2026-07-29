FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --omit=optional && npm cache clean --force

COPY bin ./bin
COPY config ./config
COPY docker ./docker
COPY src ./src

RUN mkdir -p /data/queue && chown -R node:node /app /data
USER node

ENTRYPOINT ["node", "./bin/asvp-agent.js"]
CMD ["--config", "./docker/agent.json", "run"]
