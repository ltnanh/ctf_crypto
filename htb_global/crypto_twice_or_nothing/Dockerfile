FROM rust:1.95.0-slim-bullseye

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update ; \
    apt install -y socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY challenge /app

RUN cargo build
RUN mv target/debug/twice_or_nothing /app

RUN rm -rf src Cargo.toml

EXPOSE 1337
ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:/app/twice_or_nothing"]