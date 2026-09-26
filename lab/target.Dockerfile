# Lab target servers. Debian 13 ships OpenSSL 3.5 (ML-KEM) and OpenSSH 10.
# These servers are deliberately misconfigured for demonstration. Never deploy them.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /lab/certs \
 && ssh-keygen -A

# Certificates are generated at build time, so no private keys live in the repository.
RUN cd /lab/certs \
 && OPENSSL_CONF=/dev/null openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 3650 \
      -subj "/CN=tls-legacy.lab" -keyout legacy.key -out legacy.crt \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -days 3650 \
      -subj "/CN=pqc-inventory lab" -keyout ec.key -out ec.crt

COPY entrypoint.sh /lab/entrypoint.sh

# Fail the build (not the demo) if this OpenSSH rejects any legacy algorithm name.
RUN /usr/sbin/sshd -t \
      -o KexAlgorithms=curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 \
      -o HostKeyAlgorithms=ssh-rsa,rsa-sha2-512 \
      -o Ciphers=aes128-ctr,aes128-cbc \
      -o MACs=hmac-sha2-256,hmac-sha1

ENTRYPOINT ["/lab/entrypoint.sh"]
