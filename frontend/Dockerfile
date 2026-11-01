FROM docker.io/library/node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# config.json (Keycloak realm and client) is mounted by the chart over the default.
FROM docker.io/nginxinc/nginx-unprivileged:1.30-alpine
# OS patches published since the base image was built (the image scan blocks fixable criticals); then back to the unprivileged user.
USER root
RUN apk upgrade --no-cache
USER 101
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
