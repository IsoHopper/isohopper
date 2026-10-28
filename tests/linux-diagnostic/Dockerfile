# SPDX-License-Identifier: GPL-3.0-or-later
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS build

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C SOURCE_DATE_EPOCH=0

# The base has no CA bundle. Bootstrap only this exact, hash-checked data package
# through Ubuntu's signed APT index before enabling HTTPS snapshot downloads.
RUN test "$(dpkg --print-architecture)" = amd64 && \
    apt-get update -o Acquire::Retries=0 -o Acquire::http::Timeout=30 && \
    mkdir -p /work/ca /etc/ssl/certs && cd /work/ca && \
    apt-get download ca-certificates=20260816ubuntu0.24.04.1 && \
    printf '%s  %s\n' \
      8a0a754aaafed72cc8efb8c1731808133284a84fbfc76a4fcc73fce9e01b4187 \
      ca-certificates_20260816ubuntu0.24.04.1_all.deb | sha256sum -c - && \
    dpkg-deb -x ca-certificates_20260816ubuntu0.24.04.1_all.deb extracted && \
    cat extracted/usr/share/ca-certificates/mozilla/*.crt > /etc/ssl/certs/ca-certificates.crt

# Snapshot selection freezes transitive dependencies as well as the named tools.
RUN printf 'APT::Snapshot "20261028T000000Z";\nAcquire::Retries "0";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\n' \
      > /etc/apt/apt.conf.d/50diagnostic-snapshot && \
    apt-get update && \
    apt-get install --no-install-recommends -y \
      ca-certificates=20260816ubuntu0.24.04.1 \
      systemd-ukify=255.4-1ubuntu8.18 systemd-boot-efi=255.4-1ubuntu8.18 \
      busybox-static=1:1.36.1-6ubuntu3.1 cpio=2.15+dfsg-1ubuntu2.1 gzip=1.12-1ubuntu3.2 && \
    mkdir -p /work/kernel /work/root/{bin,proc,sys,dev} /out/licenses && \
    cd /work/kernel && \
    apt-get download linux-image-6.8.0-147-generic=6.8.0-147.147 && \
    printf '%s  %s\n' \
      08432502e565a8a3b4ab13bd8b01788a0a83c9398c8a1e9350f1225991bc4fbb \
      linux-image-6.8.0-147-generic_6.8.0-147.147_amd64.deb | sha256sum -c - && \
    dpkg-deb -x ./*.deb /work/extracted && \
    dpkg-deb -f ./*.deb Package Version Source > /out/kernel-package.txt && \
    sha256sum ./*.deb > /out/kernel-package-sha256.txt && \
    apt-cache policy linux-image-6.8.0-147-generic > /out/kernel-origin.txt && \
    dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' \
      > /out/build-packages.txt && \
    cp /etc/apt/apt.conf.d/50diagnostic-snapshot /out/apt-snapshot.conf && \
    cp /work/extracted/usr/share/doc/linux-image-6.8.0-147-generic/copyright /out/licenses/linux-kernel.txt && \
    cp /usr/share/doc/busybox-static/copyright /out/licenses/busybox.txt && \
    cp /usr/share/doc/systemd-boot-efi/copyright /out/licenses/systemd.txt && \
    cp /usr/share/common-licenses/GPL-2 /usr/share/common-licenses/LGPL-2.1 /out/licenses/ && \
    cp /bin/busybox /work/root/bin/busybox

COPY init /work/root/init
RUN --network=none chmod 755 /work/root/init /work/root/bin/busybox && \
    cp /work/root/init /out/init && \
    cd /work/root && \
    find . -exec touch -h -d '@0' {} + && \
    find . -print0 | sort -z | cpio --quiet --null -o --format=newc --owner=0:0 --reproducible | \
      gzip -n > /work/initramfs.cpio.gz

RUN --network=none printf 'NAME="IsoHopper diagnostic"\nID=isohopper-test\nVERSION_ID=1\n' > /work/os-release && \
    touch /work/ukify.conf && \
    cp /usr/share/common-licenses/GPL-3 /out/licenses/ && \
    /usr/lib/systemd/ukify --config=/work/ukify.conf build \
      --stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub \
      --linux=/work/extracted/boot/vmlinuz-6.8.0-147-generic \
      --initrd=/work/initramfs.cpio.gz \
      --cmdline='console=ttyS0,115200n8 rdinit=/init panic=0 loglevel=6' \
      --os-release=@/work/os-release --uname=6.8.0-147-generic \
      --output=/out/diagnostic.efi && \
    sha256sum /work/extracted/boot/vmlinuz-6.8.0-147-generic \
      /usr/lib/systemd/boot/efi/linuxx64.efi.stub /bin/busybox /work/initramfs.cpio.gz \
      > /out/component-sha256.txt && \
    cd /out && sha256sum diagnostic.efi init > SHA256SUMS

# Export only the diagnostic and provenance files, never the builder rootfs.
FROM scratch AS artifact
COPY --from=build /out/ /
