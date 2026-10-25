FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205

ENV PNPM_HOME=/pnpm
ENV PATH=/pnpm/bin:/pnpm:/opt/bdd/bin:$PATH
ENV NEXT_TELEMETRY_DISABLED=1
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV OID_CHROMIUM_EXECUTABLE=/usr/bin/chromium
WORKDIR /workspace

RUN corepack enable && corepack prepare pnpm@11.25.0 --activate
RUN pnpm add --global @fission-ai/openspec@1.6.0
RUN apt-get update && apt-get install -y --no-install-recommends chromium python3 python3-venv git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-bdd.txt ./
RUN python3 -m venv /opt/bdd && /opt/bdd/bin/pip install --no-cache-dir -r requirements-bdd.txt

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY packages/benchmark-environment/package.json packages/benchmark-environment/package.json
COPY packages/owner-identity/package.json packages/owner-identity/package.json
COPY packages/owner-web/package.json packages/owner-web/package.json
COPY packages/owner-acceptance/package.json packages/owner-acceptance/package.json
RUN pnpm install --frozen-lockfile

ENTRYPOINT ["sh", "/workspace/infrastructure/owner-identity/runtime-entrypoint.sh"]
CMD ["sh"]
