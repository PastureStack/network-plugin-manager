ARG SOURCE_DATE_EPOCH
FROM ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03 AS snapshot-ca-bootstrap
ADD --checksum=sha256:6077d27c6b6f8b23590cb01ff877ed8c804a67a5442cc32b5a33da10d2bd0e90 \
    https://snapshot.ubuntu.com/ubuntu/20260808T000000Z/pool/main/c/ca-certificates/ca-certificates_20260601~26.04.1_all.deb \
    /tmp/ca-certificates.deb
RUN dpkg-deb -x /tmp/ca-certificates.deb /tmp/ca-certificates && \
    cp /tmp/ca-certificates/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt /snapshot-ca.crt

FROM ubuntu:26.04@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03
COPY --from=snapshot-ca-bootstrap /snapshot-ca.crt /etc/ssl/certs/ca-certificates.crt
COPY build-inputs.lock.tsv ubuntu-apt.lock /usr/share/pasturestack/manifests/

RUN rm -f /usr/bin/pebble

ARG DOCKER_VERSION=29.7.2
ARG DOCKER_CLI_SHA256
ARG IMAGE_VERSION=dev
ARG IMAGE_REVISION=unknown
ARG IMAGE_CREATED=unknown
ARG SOURCE_DATE_EPOCH
ARG UBUNTU_SNAPSHOT=20260808T000000Z
ARG UBUNTU_SNAPSHOT_BASE=https://snapshot.ubuntu.com/ubuntu

RUN set -eux; \
    . /usr/share/pasturestack/manifests/ubuntu-apt.lock; \
    locked_snapshot="$(awk -F '\t' '$1 == "ubuntu_snapshot" { print $2 }' /usr/share/pasturestack/manifests/build-inputs.lock.tsv)"; \
    locked_snapshot_base="$(awk -F '\t' '$1 == "ubuntu_snapshot_base" { print $2 }' /usr/share/pasturestack/manifests/build-inputs.lock.tsv)"; \
    test "${UBUNTU_SNAPSHOT}" = "${locked_snapshot}"; \
    test "${UBUNTU_SNAPSHOT}" = "${UBUNTU_APT_SNAPSHOT}"; \
    test "${UBUNTU_SNAPSHOT_BASE}" = "${locked_snapshot_base}"; \
    snapshot_uri="${UBUNTU_SNAPSHOT_BASE%/}/${UBUNTU_SNAPSHOT}"; \
    test "${snapshot_uri}" = "$(awk -F '\t' '$1 == "ubuntu_snapshot_uri" { print $2 }' /usr/share/pasturestack/manifests/build-inputs.lock.tsv)"; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; \
    printf 'Types: deb\nURIs: %s\nSuites: resolute resolute-updates resolute-backports resolute-security\nComponents: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' \
        "${snapshot_uri}" > /etc/apt/sources.list.d/pasturestack-snapshot.sources; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\nAcquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\nAcquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\nAcquire::http::Pipeline-Depth "0";\nAcquire::AllowInsecureRepositories "false";\nAPT::Get::AllowUnauthenticated "false";\n' > /etc/apt/apt.conf.d/80pasturestack-retries; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        "bash=${UBUNTU_APT_BASH_VERSION}" \
        "ca-certificates=${UBUNTU_APT_CA_CERTIFICATES_VERSION}" \
        "conntrack=${UBUNTU_APT_CONNTRACK_VERSION}" \
        "curl=${UBUNTU_APT_CURL_VERSION}" \
        "gawk=${UBUNTU_APT_GAWK_VERSION}" \
        "iproute2=${UBUNTU_APT_IPROUTE2_VERSION}" \
        "iptables=${UBUNTU_APT_IPTABLES_VERSION}" \
        "jq=${UBUNTU_APT_JQ_VERSION}" \
        "net-tools=${UBUNTU_APT_NET_TOOLS_VERSION}" \
        "procps=${UBUNTU_APT_PROCPS_VERSION}" \
        "psmisc=${UBUNTU_APT_PSMISC_VERSION}" \
        "tar=${UBUNTU_APT_TAR_VERSION}" \
        "util-linux=${UBUNTU_APT_UTIL_LINUX_VERSION}"; \
    { \
        printf 'record\tname\tarchitecture\tversion\n'; \
        printf 'metadata\tschema\t-\tpasturestack.dpkg-manifest/v1\n'; \
        printf 'metadata\tubuntu_snapshot\t-\t%s\n' "${UBUNTU_SNAPSHOT}"; \
        dpkg-query -W -f='package\t${binary:Package}\t${Architecture}\t${Version}\n' | LC_ALL=C sort; \
    } > /usr/share/pasturestack/manifests/runtime-ubuntu-packages.tsv; \
    ln -s / /mnt/sda1; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
    rm -f /var/log/apt/* /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache

COPY bin/docker /usr/bin/docker
COPY bin/docker-cli-go-version.txt /usr/share/pasturestack/manifests/docker-cli-go-version.txt
RUN set -eux; \
    test "${DOCKER_VERSION}" = "$(awk -F '\t' '$1 == "docker_version" { print $2 }' /usr/share/pasturestack/manifests/build-inputs.lock.tsv)"; \
    test -n "${DOCKER_CLI_SHA256}"; \
    chmod +x /usr/bin/docker; \
    echo "${DOCKER_CLI_SHA256}  /usr/bin/docker" | sha256sum -c -; \
    docker --version; \
    docker_installed_sha="$(sha256sum /usr/bin/docker | awk '{ print $1 }')"; \
    { \
        printf 'component\tdeclared_version\ttarget\tinstalled_sha256\tinstalled_version\n'; \
        printf 'docker\t%s\tlinux-%s\t%s\t%s\n' "${DOCKER_VERSION}" "$(dpkg --print-architecture)" "${docker_installed_sha}" "$(docker --version)"; \
    } > /usr/share/pasturestack/manifests/runtime-toolchain.tsv

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
