# Security Policy

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities in a public issue. Use GitHub's
private vulnerability reporting feature after it has been enabled in the
repository settings.

Include affected versions, reproduction steps, impact, and any suggested
mitigation. Do not include real broker credentials, network inventories,
database files, or other sensitive data.

## Operational safety

Fortag invokes Nmap and must only be used against networks the operator owns or
has explicit permission to assess. Configure authentication and transport
security on production MQTT brokers. The anonymous Mosquitto configuration in
the integration tests is intended only for an isolated test environment.
