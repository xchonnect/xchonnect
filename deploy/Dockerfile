# Xchonnect relay and push gateway images.
#   docker build -f deploy/Dockerfile --target relay   -t xchonnect-relay .
#   docker build -f deploy/Dockerfile --target gateway -t xchonnect-gateway .
FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p xchonnect-relay -p xchonnect-gateway \
 && strip target/release/xchonnect-relay target/release/xchonnect-gateway

# Minimal runtime: glibc + CA certificates, no shell, non-root (uid 65532).
FROM gcr.io/distroless/cc-debian12:nonroot AS relay
COPY --from=build /src/target/release/xchonnect-relay /usr/local/bin/xchonnect-relay
ENV XCHONNECT_LISTEN=0.0.0.0:8787
EXPOSE 8787
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/xchonnect-relay"]

FROM gcr.io/distroless/cc-debian12:nonroot AS gateway
COPY --from=build /src/target/release/xchonnect-gateway /usr/local/bin/xchonnect-gateway
ENV XCHONNECT_GATEWAY_LISTEN=0.0.0.0:8788
EXPOSE 8788
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/xchonnect-gateway"]
