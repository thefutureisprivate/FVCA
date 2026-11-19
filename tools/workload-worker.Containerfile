FROM registry.fedoraproject.org/fedora@sha256:3156944cdf17f20c4076165836538075ef3f0f8252d4b00522b49cefd58056bb
RUN dnf -y --setopt=gpgcheck=True --disable-repo=fedora-cisco-openh264 install \
       umoci-0.6.0-4.fc45 erofs-utils-1.9.4-2.fc45 veritysetup-2.8.8-1.fc45 \
       python3-3.15.2-1.fc45 zstd-1.5.7-6.fc45 \
    && dnf clean all
