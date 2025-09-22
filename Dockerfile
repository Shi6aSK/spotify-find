# Simple Dockerfile for running the Spotify-find server
# Uses Node 18 LTS
FROM node:18-alpine

WORKDIR /usr/src/app

# Copy package files if present (optional) and install dependencies
COPY package.json package-lock.json* ./
RUN if [ -f package.json ]; then npm ci --production; fi

# Copy the app
COPY . .

EXPOSE 3000

# Default to PORT env var or 3000
ENV PORT=3000
CMD ["node", "server.js"]
