FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev cmake make g++ perl linux-headers
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

### Minimal run-time image: no shell, no package manager, non-root.
FROM alpine:3.21
RUN adduser -D -H -u 10001 tmate && mkdir -p /keys && chown tmate:tmate /keys
COPY --from=build /src/target/release/tmate-server-rs /usr/local/bin/tmate-server-rs
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
USER tmate
VOLUME /keys
EXPOSE 2200
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
