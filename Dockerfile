FROM node:25-bookworm-slim AS backend-build
WORKDIR /app/backend

COPY backend/package.json backend/package-lock.json ./
RUN npm ci

COPY backend/tsconfig.json ./
COPY backend/src ./src
RUN npm run build

FROM node:25-bookworm-slim AS frontend-build
WORKDIR /app/stage-planner

ARG VITE_IDLE_LOGOUT_MINUTES
ENV VITE_IDLE_LOGOUT_MINUTES=${VITE_IDLE_LOGOUT_MINUTES}

COPY stage-planner/package.json stage-planner/package-lock.json ./
RUN npm ci

COPY stage-planner/tsconfig*.json ./
COPY stage-planner/vite.config.ts stage-planner/index.html ./
COPY stage-planner/public ./public
COPY stage-planner/src ./src
RUN npm run build

FROM alpine:3.20
WORKDIR /opt/stageplanner

COPY --from=backend-build /app/backend/dist ./backend/dist
COPY --from=frontend-build /app/stage-planner/dist ./stage-planner/dist
