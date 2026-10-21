# norcaster-counterparty: the self-hosted Shared Record component (draft protocol, in development).
# Red Hat Universal Base Image 9, as Norcaster's own images: free to redistribute while only UBI
# content is added. Every dependency installs from a hash-pinned wheel (docker/lock.sh).
FROM registry.access.redhat.com/ubi9/python-312-minimal:9.8-1791925965@sha256:8d9955078019f81659230b378bf916da4cd63ccc82f7f88a40ab642730cb776f AS build
USER 0
WORKDIR /src
COPY docker/build-requirements.txt /tmp/build-requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/build-requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /tmp/wheels .

FROM registry.access.redhat.com/ubi9/python-312-minimal:9.8-1791925965@sha256:8d9955078019f81659230b378bf916da4cd63ccc82f7f88a40ab642730cb776f
# The base image runs as 1001; the build steps run as root, the image as 10001 (below). Its group is
# 0: OpenShift runs an image as an arbitrary uid in group 0, so what it may write is group 0 and
# group-writable. /work is where you mount counterparty.json and its state_dir.
USER 0
RUN useradd --system --uid 10001 --gid 0 --home-dir /home/norcaster --create-home \
       --shell /usr/sbin/nologin norcaster \
    && mkdir -p /work && chown 10001:0 /work \
    && chgrp -R 0 /home/norcaster /work && chmod -R g=u /home/norcaster /work
# norcaster-verify and its dependencies, exact versions with hashes. Before norcaster-verify is on
# PyPI, a local build serves its wheel over HTTP and passes --build-arg PIP_FIND_LINKS=<that URL>
# and --build-arg PIP_TRUSTED_HOST=<its host>; the hash pin still applies.
ARG PIP_FIND_LINKS=""
ARG PIP_TRUSTED_HOST=""
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
# The component itself, built in the first stage from this repository's source; no dependencies.
COPY --from=build /tmp/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-deps /tmp/wheels/*.whl && rm -rf /tmp/wheels
COPY LICENSE /licenses/

# Under a read-only root filesystem only /tmp and the mounted /work are writable. HOME, USER and
# LOGNAME are set so nothing needs a passwd entry for an arbitrary uid.
ENV PYTHONDONTWRITEBYTECODE=1 \
    XDG_CACHE_HOME=/tmp/.cache \
    HOME=/home/norcaster \
    USER=norcaster \
    LOGNAME=norcaster

# Red Hat's required labels, replacing the base image's. The release workflow sets the version.
ARG NORCASTER_VERSION=dev
ARG NORCASTER_RELEASE=0
LABEL name="norcaster-counterparty" \
      vendor="Navego AB" \
      version="${NORCASTER_VERSION}" \
      release="${NORCASTER_RELEASE}" \
      summary="Norcaster Shared Record counterparty (self-hosted)" \
      description="Your side of a Shared Record with a partner: your own keys and records, receipts and acknowledgements for agent tool calls, a local MCP proxy for agents, log witnessing and evidence export. No Norcaster account needed. Draft protocol, in development." \
      maintainer="Navego AB <security@norcaster.com>" \
      url="https://www.norcaster.com" \
      io.k8s.display-name="Norcaster Shared Record counterparty" \
      io.k8s.description="Self-hosted Shared Record counterparty: keys, receipts, acknowledgements, witnessing, export." \
      io.openshift.tags="norcaster,shared-record" \
      org.opencontainers.image.source="https://github.com/norcaster/counterparty" \
      org.opencontainers.image.licenses="Apache-2.0" \
      usage="docker run --rm -v \"\$PWD:/work\" ghcr.io/norcaster/counterparty --config counterparty.json witness"

# The local MCP proxy (proxy serve) listens here; it binds 127.0.0.1 unless proxy.json sets "host"
# (0.0.0.0 when another container reaches it). Every HTTP endpoint needs the proxy's bearer token,
# so check health with a TCP probe on this port.
EXPOSE 8790

WORKDIR /work
USER 10001
ENTRYPOINT ["norcaster-counterparty"]
CMD ["--help"]
