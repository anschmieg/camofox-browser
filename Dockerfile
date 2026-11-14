# Camofox browser server — self-contained build for Coolify.
#
# Coolify's inline-dockerfile deployments have no build context, so the pinned
# source is fetched from the deployment repo at build time. The Camoufox
# browser binary is fetched with camoufox-js itself (the same code path as the
# reference deployment), which resolves the version and post-processes the
# binary; a manual zip download produced a binary whose Juggler protocol was
# missing Browser.setDownloadOptions.
FROM node:22-slim

ARG SOURCE_REPO=https://github.com/anschmieg/camofox-browser.git
ARG SOURCE_REF=cd15f82e667289d931f73f621dea7ad4503bcacd

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgtk-3-0 \
    libdbus-glib-1-2 \
    libxt6 \
    libasound2 \
    libx11-xcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    libegl1-mesa \
    libgl1-mesa-dri \
    libgbm1 \
    xvfb \
    fonts-liberation \
    fonts-noto-color-emoji \
    fontconfig \
    ca-certificates \
    curl \
    unzip \
    git \
    python3 \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# yt-dlp for the YouTube transcript plugin.
RUN curl -L -o /usr/local/bin/yt-dlp "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp" \
    && chmod 755 /usr/local/bin/yt-dlp

WORKDIR /app

# Pinned source from the deployment repo.
RUN git clone --depth 1 --branch master "$SOURCE_REPO" /tmp/src \
    && git -C /tmp/src fetch --depth 1 origin "$SOURCE_REF" \
    && git -C /tmp/src checkout --quiet "$SOURCE_REF" \
    && cp -a /tmp/src/. /app/ \
    && rm -rf /tmp/src

RUN npm ci --omit=dev

# Camoufox binary via camoufox-js (resolves version + arch, post-processes).
RUN node node_modules/camoufox-js/dist/__main__.js fetch

RUN sh scripts/install-plugin-deps.sh

ENV NODE_ENV=production
ENV CAMOFOX_PORT=9379

EXPOSE 9379

CMD ["sh", "-c", "node --max-old-space-size=${MAX_OLD_SPACE_SIZE:-512} server.js"]
