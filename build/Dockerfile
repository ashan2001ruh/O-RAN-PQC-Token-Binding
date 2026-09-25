# Minimal image for one statically linked binary from out/bin (the build context).
FROM scratch
ARG BIN
COPY ${BIN} /app
USER 65532:65532
ENTRYPOINT ["/app"]
