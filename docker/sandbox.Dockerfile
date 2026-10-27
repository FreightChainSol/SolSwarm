# Tools for the audit sandbox. The target's own Dockerfile is never used.
# Runtime egress is not decided here; sandbox.sh puts the container on an
# internal network behind audit/scripts/sandbox-proxy.mjs.
FROM node:22-bookworm-slim AS nodebin

FROM rust:1.89-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 pkg-config libssl-dev build-essential bzip2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nodebin /usr/local/bin/node /usr/local/bin/node
COPY --from=nodebin /usr/local/lib/node_modules /usr/local/lib/node_modules
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && ln -sf ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && corepack enable \
    && corepack prepare pnpm@10 --activate \
    && node --version && npm --version && pnpm --version

RUN cargo install cargo-audit --version 0.22.2 --locked

# Provision the declared toolchain completely: reviewer tests run with a read-only root.
# Current Agave/LiteSVM test crates declare rust-version 1.97.1; a newer rustc still builds older crates.
RUN rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy \
    && rustup run 1.99.1 rustc --version
ENV RUSTUP_TOOLCHAIN=1.99.1

ARG SOLANA_PLATFORM_TOOLS_VERSION=v1.54
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
      amd64) a=x86_64; sha=fcc41631c7f77561bf5412218bf297501dccf0305ea280f338f0ace2aab9f31e ;; \
      arm64) a=aarch64; sha=f62812dd96b6b1c8e0e2cf677146912c58c83e95d762c30e89230d669f9c2e6a ;; \
      *) echo "unsupported arch $arch" >&2; exit 1 ;; \
    esac \
    && mkdir -p /opt/platform-tools \
    && curl -fsSL -o /tmp/platform-tools.tar.bz2 "https://github.com/anza-xyz/platform-tools/releases/download/${SOLANA_PLATFORM_TOOLS_VERSION}/platform-tools-linux-${a}.tar.bz2" \
    && printf '%s  /tmp/platform-tools.tar.bz2\n' "$sha" | sha256sum -c - \
    && tar -xjf /tmp/platform-tools.tar.bz2 -C /opt/platform-tools \
    && chmod -R a+rX /opt/platform-tools \
    && rm -f /tmp/platform-tools.tar.bz2 \
    && /opt/platform-tools/rust/bin/rustc --version \
    && /opt/platform-tools/rust/bin/cargo --version

ARG GITLEAKS_VERSION=8.24.3
ARG SEMGREP_VERSION=1.181.0
ARG SEMGREP_RULES_REV=17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

COPY prepare-scanner-rules.py /opt/prepare-scanner-rules.py
COPY prepare-cargo-cache.py /opt/prepare-cargo-cache.py
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) a=x64 ;; arm64) a=arm64 ;; *) exit 1 ;; esac \
    && mkdir -p /tmp/gitleaks /opt/audit-scanners \
    && curl -fsSL -o /tmp/gitleaks/tool.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${a}.tar.gz" \
    && curl -fsSL -o /tmp/gitleaks/checksums.txt "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
    && cd /tmp/gitleaks \
    && mv tool.tar.gz "gitleaks_${GITLEAKS_VERSION}_linux_${a}.tar.gz" \
    && grep " gitleaks_${GITLEAKS_VERSION}_linux_${a}.tar.gz$" checksums.txt | sha256sum -c - \
    && tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_${a}.tar.gz" -C /usr/local/bin gitleaks \
    && curl -fsSL -o /opt/audit-scanners/gitleaks.toml "https://raw.githubusercontent.com/gitleaks/gitleaks/v${GITLEAKS_VERSION}/config/gitleaks.toml" \
    && curl -fsSL -o /tmp/rules.tar.gz "https://codeload.github.com/semgrep/semgrep-rules/tar.gz/${SEMGREP_RULES_REV}" \
    && mkdir /tmp/semgrep-rules \
    && tar -xzf /tmp/rules.tar.gz --strip-components=1 -C /tmp/semgrep-rules \
    && /opt/semgrep/bin/python /opt/prepare-scanner-rules.py \
    && semgrep scan --validate --config /opt/audit-scanners/semgrep-rules --metrics=off --disable-version-check \
    && git clone --depth=1 https://github.com/RustSec/advisory-db /opt/audit-scanners/advisory-db \
    && git -C /opt/audit-scanners/advisory-db rev-parse HEAD > /opt/audit-scanners/rustsec-revision.txt \
    && printf '%s\n' "gitleaks=${GITLEAKS_VERSION}" "semgrep=${SEMGREP_VERSION}" "rules=${SEMGREP_RULES_REV}" > /opt/audit-scanners/versions.txt \
    && date -u +%FT%TZ > /opt/audit-scanners/prepared-at.txt \
    && sha256sum /opt/audit-scanners/semgrep-rules /opt/audit-scanners/gitleaks.toml > /opt/audit-scanners/rules.sha256 \
    && rm -rf /tmp/gitleaks /tmp/rules.tar.gz /tmp/semgrep-rules

ARG TARGETARCH
ARG OSV_VERSION=2.7.0
RUN arch="${TARGETARCH:-$(dpkg --print-architecture)}" \
    && case "$arch" in \
      amd64) a=amd64 ;; \
      arm64) a=arm64 ;; \
      *) echo "unsupported arch $arch" >&2; exit 1 ;; \
    esac \
    && curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${a}" \
    && chmod 755 /usr/local/bin/osv-scanner \
    && osv-scanner --version

# The OSV API is not on the runtime allowlist. Databases are fetched while
# this image is built, from throwaway lockfiles that each contain one real
# package (an empty lockfile does not trigger a download), then scans stay offline.
ENV XDG_CACHE_HOME=/opt/osv-cache
RUN mkdir -p /tmp/osv-seed /opt/osv-cache \
    && printf '%s\n' 'version = 3' '[[package]]' 'name = "libc"' 'version = "0.2.155"' \
         'source = "registry+https://github.com/rust-lang/crates.io-index"' \
         'checksum = "1111111111111111111111111111111111111111111111111111111111111111"' \
         > /tmp/osv-seed/Cargo.lock \
    && printf '%s\n' \
         '{' \
         '  "name": "seed",' \
         '  "version": "1.0.0",' \
         '  "lockfileVersion": 3,' \
         '  "requires": true,' \
         '  "packages": {' \
         '    "": {' \
         '      "name": "seed",' \
         '      "version": "1.0.0",' \
         '      "dependencies": { "left-pad": "1.3.0" }' \
         '    },' \
         '    "node_modules/left-pad": {' \
         '      "version": "1.3.0",' \
         '      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"' \
         '    }' \
         '  }' \
         '}' \
         > /tmp/osv-seed/package-lock.json \
    && osv-scanner scan source --download-offline-databases --offline -r /tmp/osv-seed \
    && test -s /opt/osv-cache/osv-scalibr/crates.io/all.zip \
    && test -s /opt/osv-cache/osv-scalibr/npm/all.zip \
    && chmod -R a+rX /opt/osv-cache \
    && sha256sum /opt/osv-cache/osv-scalibr/crates.io/all.zip /opt/osv-cache/osv-scalibr/npm/all.zip > /opt/audit-scanners/databases.sha256 \
    && rm -rf /tmp/osv-seed

# Classic Yarn for a frozen install. A Berry lockfile activates Yarn 4 at
# runtime through the npm-registry allowlist.
RUN corepack prepare yarn@1.22.22 --activate && yarn --version

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin sandbox

COPY entrypoint.sh /usr/local/bin/sandbox-entrypoint
RUN chmod 755 /usr/local/bin/sandbox-entrypoint

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sandbox-entrypoint"]
