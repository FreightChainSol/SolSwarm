FROM rust:1.99-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake libclang-dev libssl-dev pkg-config protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
ENV CARGO_BUILD_JOBS=1 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_PANIC=unwind
# The entry gates test the real CLI binary; package that exact artifact.
RUN --mount=type=cache,id=freightchain-grok-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=freightchain-grok-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=freightchain-grok-target,target=/build/target \
    cargo test --locked -p freightchain-grok-review \
    && cp /build/target/debug/freightchain-grok-review /broker

FROM node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
# The official CLI is used only for a fresh device login, never source inference.
RUN npm install --global @xai-official/grok@1.0.52 && grok --version
COPY --from=build /broker /usr/local/bin/freightchain-grok-review
COPY --from=build /build/LICENSE /build/THIRD-PARTY-NOTICES /usr/share/doc/freightchain-grok-review/
RUN mkdir -p /home/reviewer/.grok /session && chown -R 10001:10001 /home/reviewer /session
LABEL freightchain.grok.source="2bdd1d6a6369de0e8c68132ea4539e9abd9e14a8"
ENV HOME=/home/reviewer GROK_HOME=/home/reviewer/.grok
USER 10001:10001
WORKDIR /session
ENTRYPOINT ["/usr/local/bin/freightchain-grok-review"]
