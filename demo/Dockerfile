# Demo workload image. Debian slim plus curl, the kind of image a monitoring or
# CI agent ships with. Nothing in the image is malicious, the risk comes from
# how it is run.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
