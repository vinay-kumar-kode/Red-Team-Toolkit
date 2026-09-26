# Lab certificate. Self-signed and long-lived on purpose; never reuse it.
# Regenerate with: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 800 -nodes -subj "/CN=lab.invalid" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
