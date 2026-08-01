# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS base
WORKDIR /app
RUN corepack enable

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/
COPY apps/dashboard/package.json apps/dashboard/
COPY packages/agent/package.json packages/agent/
COPY packages/contracts/package.json packages/contracts/
COPY packages/storage/package.json packages/storage/
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
RUN pnpm run build

FROM base AS api
ENV NODE_ENV=production
ENV PORT=8788
COPY --from=build /app /app
EXPOSE 8788
CMD ["pnpm", "--filter", "@sentinel-x/api", "start"]
