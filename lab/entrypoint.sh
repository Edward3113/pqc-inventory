#!/bin/sh
# Starts one lab target. LAB_ROLE selects which deliberately configured server to run.
# Every server here is intentionally configured for demonstration; never deploy these
# settings anywhere real.
set -eu

case "${LAB_ROLE:?set LAB_ROLE}" in
  tls-legacy)
    # TLS 1.0-1.2 only, RSA-1024 certificate signed with SHA-1, static-RSA and CBC suites.
    # @SECLEVEL=0 is required for OpenSSL 3.x to accept any of this.
    exec openssl s_server -accept 443 -www -quiet \
      -cert /lab/certs/legacy.crt -key /lab/certs/legacy.key \
      -min_protocol TLSv1 -max_protocol TLSv1.2 \
      -cipher 'AES128-SHA:AES256-SHA:ECDHE-RSA-AES128-SHA:@SECLEVEL=0'
    ;;
  tls-classical)
    # A well-run modern server: TLS 1.2/1.3, AEAD only, ECDSA P-256. No post-quantum.
    exec openssl s_server -accept 443 -www -quiet \
      -cert /lab/certs/ec.crt -key /lab/certs/ec.key \
      -cipher 'ECDHE+AESGCM:ECDHE+CHACHA20' -groups X25519:P-256
    ;;
  tls-pq)
    # Same as tls-classical, plus hybrid post-quantum key exchange (ML-KEM).
    exec openssl s_server -accept 443 -www -quiet \
      -cert /lab/certs/ec.crt -key /lab/certs/ec.key \
      -cipher 'ECDHE+AESGCM:ECDHE+CHACHA20' -groups X25519MLKEM768:X25519:P-256
    ;;
  ssh-modern)
    # Stock OpenSSH 10 defaults, which include mlkem768x25519-sha256.
    exec /usr/sbin/sshd -D -e
    ;;
  ssh-legacy)
    # Classical-only key exchange with SHA-1 options, SHA-1 RSA host key signatures, CBC.
    exec /usr/sbin/sshd -D -e \
      -o KexAlgorithms=curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 \
      -o HostKeyAlgorithms=ssh-rsa,rsa-sha2-512 \
      -o Ciphers=aes128-ctr,aes128-cbc \
      -o MACs=hmac-sha2-256,hmac-sha1
    ;;
  *)
    echo "unknown LAB_ROLE: $LAB_ROLE" >&2
    exit 1
    ;;
esac
