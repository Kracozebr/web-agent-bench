FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205

ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm:$PATH
WORKDIR /workspace

RUN corepack enable && corepack prepare pnpm@11.25.0 --activate

COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY --chown=node:node packages/benchmark-environment/package.json packages/benchmark-environment/package.json
RUN pnpm install --frozen-lockfile

COPY --chown=node:node packages/benchmark-environment packages/benchmark-environment
COPY --chown=node:node infrastructure/benchmark-environment infrastructure/benchmark-environment
RUN pnpm --filter @web-agent-bench/benchmark-environment build

ENV NODE_ENV=production
USER node
CMD ["node", "packages/benchmark-environment/dist/index.js"]
