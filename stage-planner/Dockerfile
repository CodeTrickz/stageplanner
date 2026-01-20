FROM node:20-bookworm-slim AS build
WORKDIR /app

ARG VITE_IDLE_LOGOUT_MINUTES
ENV VITE_IDLE_LOGOUT_MINUTES=${VITE_IDLE_LOGOUT_MINUTES}

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig*.json ./
COPY vite.config.ts index.html ./
COPY public ./public
COPY src ./src

RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html
EXPOSE 8080

