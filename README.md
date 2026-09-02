# Fortag Backend

Fortag Backend is a stateful local-network security scanner. It discovers hosts
on private IPv4 networks, performs targeted Nmap service scans, stores history
in SQLite, and publishes state and commands through MQTT API v2.

This repository contains the complete backend source, unit tests, integration
tests, and container build configuration. The Home Assistant integration and
web panel are separate components.

## Features

- Two-phase Nmap scanning: host discovery followed by per-host service scans.
- Strict scan-target validation limited to RFC 1918 IPv4 networks.
- SQLite schema migrations and durable device/port history.
- Identity bridging for devices that rotate locally administered MAC addresses.
- UUID-scoped MQTT API v2 topics and command-result correlation.
- Home Assistant approval leases that prevent unapproved scanning.
- Linux database locking to prevent concurrent writers.
- Multi-platform container builds for `linux/amd64` and `linux/arm64`.

## Requirements

- Docker with the Buildx and Compose plugins.
- An MQTT broker reachable from the scanner.
- Linux host networking for reliable Layer 2 discovery.

No Go installation is required on the host.

## Build

Build a local image from the repository root:

```bash
docker build \
  --build-arg BUILD_VERSION=dev \
  -t fortag-backend:dev \
  -f scanner/Dockerfile \
  scanner
```

## Run

Create a local environment file and do not commit it:

```env
MQTT_USER=
MQTT_PASSWORD=
```

Restrict access to it:

```bash
chmod 600 fortag.env
```

Then edit the broker URL in `compose.yaml` and start the scanner:

```bash
docker compose --env-file fortag.env up -d --build
```

The database is stored in the named `fortag-data` volume. The scanner uses host
networking because Nmap discovery needs direct access to the local network.

Only scan networks you own or are explicitly authorized to assess.

## Configuration

The scanner accepts these command-line flags:

| Flag | Default | Description |
| --- | --- | --- |
| `-db` | `scanner.db` | SQLite database path. |
| `-mqtt` | `tcp://localhost:1883` | MQTT broker URL. |
| `-user` | `$MQTT_USER` | MQTT username. |
| `-password` | `$MQTT_PASSWORD` | MQTT password. Prefer the environment variable to avoid shell history exposure. |
| `-range` | auto-detected | Private IPv4 address or CIDR to scan. |
| `-freq` | `8h` | Interval between scan cycles. |
| `-dump` | disabled | Dump database contents as JSON and exit. |

If `-range` is omitted, Fortag detects a local RFC 1918 interface. A range can
also be changed through MQTT. The scanner rejects public and boundary-crossing
CIDRs.

## Tests

Run unit tests in a container:

```bash
./run-tests.sh unit
```

Run the full unit and Docker-based MQTT integration suite:

```bash
./run-tests.sh all
```

The integration suite starts an isolated Mosquitto broker that permits
anonymous access only for the lifetime of the test environment. Do not reuse
that broker configuration in production.

## Release image

To build and push a multi-platform image, authenticate to your chosen registry
and provide the full image name explicitly:

```bash
IMAGE=ghcr.io/OWNER/fortag-backend ./build-and-push.sh beta 1.1.0-rc.2
IMAGE=ghcr.io/OWNER/fortag-backend ./build-and-push.sh stable 1.1.0
```

Beta builds publish the exact version and `beta`. Stable builds publish the
exact version, its major/minor tag, and `latest`.

## Protocol

See [docs/API.md](docs/API.md) for MQTT topics and payloads. MQTT API v2 is an
incompatible change from v1; consumers must support the UUID-scoped namespace.

## Security

See [SECURITY.md](SECURITY.md). Never commit broker credentials, environment
files, SQLite databases, network scan output, or private infrastructure URLs.

## License

Fortag Backend is distributed under the MIT License. See [LICENSE](LICENSE).
