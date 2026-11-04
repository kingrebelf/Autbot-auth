FROM node:24-bookworm-slim
ENV NODE_ENV=production AUTBOT_CONFIG_DIR=/data HOST=0.0.0.0 PORT=3000
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && mkdir -p /data && chown node:node /data
COPY --chown=node:node src ./src
USER node
VOLUME ["/data"]
EXPOSE 3000
CMD ["node", "src/server.mjs"]
