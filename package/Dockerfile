FROM alpine:3.23@sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3

COPY build-inputs.lock.tsv alpine-apk.lock /usr/share/pasturestack/manifests/

ARG IMAGE_VERSION=dev
ARG IMAGE_REVISION=unknown
ARG IMAGE_CREATED=unknown
ARG ALPINE_BRANCH=3.23

RUN set -eux; \
    . /usr/share/pasturestack/manifests/alpine-apk.lock; \
    test "${ALPINE_BRANCH}" = "${ALPINE_APK_BRANCH}"; \
    apk add --no-cache \
        "bash=${ALPINE_APK_BASH_VERSION}" \
        "ca-certificates=${ALPINE_APK_CA_CERTIFICATES_VERSION}" \
        "conntrack-tools=${ALPINE_APK_CONNTRACK_TOOLS_VERSION}" \
        "curl=${ALPINE_APK_CURL_VERSION}" \
        "gawk=${ALPINE_APK_GAWK_VERSION}" \
        "iproute2=${ALPINE_APK_IPROUTE2_VERSION}" \
        "iptables=${ALPINE_APK_IPTABLES_VERSION}" \
        "jq=${ALPINE_APK_JQ_VERSION}" \
        "net-tools=${ALPINE_APK_NET_TOOLS_VERSION}" \
        "procps-ng=${ALPINE_APK_PROCPS_NG_VERSION}" \
        "psmisc=${ALPINE_APK_PSMISC_VERSION}" \
        "tar=${ALPINE_APK_TAR_VERSION}" \
        "util-linux=${ALPINE_APK_UTIL_LINUX_VERSION}"; \
    { \
        printf 'record\tname-version\n'; \
        printf 'metadata\talpine-branch-%s\n' "${ALPINE_BRANCH}"; \
        apk info -v | LC_ALL=C sort | sed 's/^/package\t/'; \
    } > /usr/share/pasturestack/manifests/runtime-alpine-packages.tsv; \
    ln -s / /mnt/sda1

COPY bin/network-plugin-manager package/start.sh package/platform-entrypoint.sh package/update-platform-ca /usr/bin/
RUN sed -i 's/\r$//' /usr/bin/start.sh /usr/bin/platform-entrypoint.sh /usr/bin/update-platform-ca && \
    chmod 0755 /usr/bin/network-plugin-manager /usr/bin/start.sh /usr/bin/platform-entrypoint.sh /usr/bin/update-platform-ca

COPY LICENSE COMPATIBILITY.md ORIGIN.md SECURITY.md THIRD_PARTY_NOTICES.md /licenses/
COPY LICENSES /licenses/third-party/

LABEL org.opencontainers.image.title="PastureStack Network Plugin Manager" \
      org.opencontainers.image.description="Host network reconciliation service for PastureStack" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/PastureStack/network-plugin-manager" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.created="${IMAGE_CREATED}"

ENTRYPOINT ["/usr/bin/platform-entrypoint.sh", "/usr/bin/start.sh"]
CMD ["network-plugin-manager"]
