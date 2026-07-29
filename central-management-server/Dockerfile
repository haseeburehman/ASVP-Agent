FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app/central-management-server

COPY central-management-server/package.json central-management-server/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY central-management-server/src ./src
COPY src/security/task-envelope.js /app/src/security/task-envelope.js
RUN mkdir -p /data && chown -R node:node /app /data
USER node

EXPOSE 5040
CMD ["node", "src/server.js"]
