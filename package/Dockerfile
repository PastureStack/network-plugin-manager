ARG SOURCE_DATE_EPOCH
FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb AS snapshot-ca-bootstrap
ADD --checksum=sha256:6077d27c6b6f8b23590cb01ff877ed8c804a67a5442cc32b5a33da10d2bd0e90 \
    https://snapshot.ubuntu.com/ubuntu/20260722T164940Z/pool/main/c/ca-certificates/ca-certificates_20260601~26.04.1_all.deb \
    /tmp/ca-certificates.deb
RUN dpkg-deb -x /tmp/ca-certificates.deb /tmp/ca-certificates && \
    cp /tmp/ca-certificates/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt /snapshot-ca.crt

FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb
COPY --from=snapshot-ca-bootstrap /snapshot-ca.crt /etc/ssl/certs/ca-certificates.crt

RUN rm -f /usr/bin/pebble

ARG DOCKER_VERSION=29.6.2
ARG DOCKER_LINUX_AMD64_SHA256=d6204aea92238e2453d5445c885b9d2e5eb8f82915568ec50edf9dbe12a3ac74
ARG IMAGE_VERSION=dev
ARG IMAGE_REVISION=unknown
ARG IMAGE_CREATED=unknown
ARG SOURCE_DATE_EPOCH
ARG UBUNTU_SNAPSHOT=20260722T164940Z
ARG UBUNTU_SNAPSHOT_BASE=https://snapshot.ubuntu.com/ubuntu

RUN set -eux; \
    snapshot_uri="${UBUNTU_SNAPSHOT_BASE%/}/${UBUNTU_SNAPSHOT}"; \
    find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) -exec sed -i \
        -e "s|http://security.ubuntu.com/ubuntu|${snapshot_uri}|g" \
        -e "s|http://archive.ubuntu.com/ubuntu|${snapshot_uri}|g" {} +; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\nAcquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\nAcquire::http::Pipeline-Depth "0";\n' > /etc/apt/apt.conf.d/80pasturestack-retries; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        conntrack \
        curl \
        gawk \
        iproute2 \
        iptables \
        jq \
        net-tools \
        procps \
        psmisc \
        tar \
        util-linux; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 10 --max-time 300 \
        -o /tmp/docker.tgz "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz"; \
    echo "${DOCKER_LINUX_AMD64_SHA256}  /tmp/docker.tgz" | sha256sum -c -; \
    tar xzf /tmp/docker.tgz -C /usr/bin --strip-components=1 docker/docker; \
    chmod +x /usr/bin/docker; \
    rm -f /tmp/docker.tgz; \
    ln -s / /mnt/sda1; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
    rm -f /var/log/apt/* /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache

COPY bin/network-plugin-manager package/start.sh package/platform-entrypoint.sh package/update-platform-ca /usr/bin/
RUN sed -i 's/\r$//' /usr/bin/start.sh /usr/bin/platform-entrypoint.sh /usr/bin/update-platform-ca && \
    chmod +x /usr/bin/network-plugin-manager /usr/bin/start.sh /usr/bin/platform-entrypoint.sh /usr/bin/update-platform-ca

COPY LICENSE COMPATIBILITY.md ORIGIN.md SECURITY.md THIRD_PARTY_NOTICES.md /licenses/
COPY LICENSES /licenses/third-party/

LABEL org.opencontainers.image.title="PastureStack Network Plugin Manager" \
      org.opencontainers.image.description="Host network reconciliation service for PastureStack" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/PastureStack/network-plugin-manager" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/network-plugin-manager/blob/main/README.md" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.created="${IMAGE_CREATED}"

ENTRYPOINT ["/usr/bin/platform-entrypoint.sh", "/usr/bin/start.sh"]
CMD ["network-plugin-manager"]
