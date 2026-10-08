FROM node:20-alpine

# Docker CLI only — orchestrator issues `docker run`/`docker inspect`/`docker kill`
# against worker images on the host's Docker daemon via the mounted socket.
# No daemon needed inside this container.
RUN apk add --no-cache docker-cli bash

WORKDIR /app
COPY package.json .
RUN npm install
COPY src/ src/

# HTTP/SSE mode port (only used if MCP_HTTP=true)
EXPOSE 3002

CMD ["node", "src/index.js"]
