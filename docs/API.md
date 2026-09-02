# Fortag Network Security Scanner API Reference

This document defines the communication APIs and payload schemas for the Fortag system, including the MQTT messaging interface and the Home Assistant WebSocket API.

---

## 1. MQTT API Reference

All MQTT messages use JSON payloads (except `scan_now` which is empty). The default topic prefix is `fortag/scanner`.

### 1.1. Outbound Topics (Published by Go Scanner)

#### `fortag/scanner/state`
Publishes the full state of the network scan. This message is published with the **retain flag set to true** so that new clients receive the latest state immediately upon subscription.

*   **Trigger:** Scanner startup after database migrations and before the first
    scan; complete scan execution; or database modification (Rename,
    Acknowledge, Update Range). Startup publication waits for MQTT to confirm
    the retained message before scanning begins.
*   **JSON Schema:**
    ```json
    {
      "api_version": "integer (currently 1)",
      "scanner_version": "string (scanner build version)",
      "schema_version": "integer (SQLite schema version, currently 1)",
      "last_scan": "string (RFC3339 timestamp)",
      "duration": "string (seconds, e.g., '12.34s')",
      "scan_range": "string (active range persisted in SQLite)",
      "hosts": [
        {
          "mac": "string (hex format, upper case)",
          "ip": "string (IPv4 address)",
          "hostname": "string",
          "custom_name": "string (empty if not customized)",
          "os": "string (OS guess string)",
          "ports": [
            {
              "port": "integer",
              "protocol": "string (e.g., 'tcp')",
              "service": "string (e.g., 'ssh')",
              "state": "string (e.g., 'open')",
              "scripts": "string (concatenated script output)",
              "is_new": "boolean",
              "is_acknowledged": "boolean"
            }
          ],
          "is_new_host": "boolean",
          "is_acknowledged": "boolean",
          "is_randomized": "boolean",
          "is_current": "boolean (successfully identified in the latest completed scan)",
          "matched_from": "string (MAC address of bridged source, empty if not bridged)"
        }
      ]
    }
    ```

Only ports whose latest successful host scan reports exact Nmap state `open`
are included in scanner state. Closed and filtered observations remain in
SQLite as history but are not published as current exposure. A transition from
any non-open state back to `open` is emitted as a new, unacknowledged port
exposure.

#### `fortag/scanner/progress`
Publishes real-time scanning progress updates.

*   **Trigger:** Transition between scanning phases (host discovery, targeted port scan, idle).
*   **JSON Schema:**
    ```json
    {
      "status": "string (scanning_hosts | scanning_ports | idle)",
      "target": "string (subnet range or IP address being scanned)"
    }
    ```

#### `fortag/scanner/alert`
Publishes security events for new hosts or new open ports.

*   **Trigger:** Discovery of a truly new host or a new open port.
*   **JSON Schema (New Host):**
    ```json
    {
      "type": "new_host",
      "mac": "string (MAC address)",
      "ip": "string (IP address)"
    }
    ```
*   **JSON Schema (New Port):**
    ```json
    {
      "type": "new_port",
      "mac": "string (MAC address)",
      "port": "integer",
      "protocol": "string (e.g., 'tcp')"
    }
    ```

Alerts are published after scan results have been committed to SQLite. A newly
discovered host emits one `new_host` alert and one `new_port` alert for each newly
discovered open port.

---

### 1.2. Inbound Topics (Subscribed by Go Scanner)

#### `fortag/scanner/command/rename`
Instructs the scanner to assign a friendly name to a device.

*   **JSON Schema:**
    ```json
    {
      "mac": "string (MAC address)",
      "name": "string (new name)"
    }
    ```

#### `fortag/scanner/command/acknowledge`
Acknowledges a security warning for a new host or a new open port, silences alerts, and marks the item as reviewed.

*   **JSON Schema (Acknowledge Host):**
    ```json
    {
      "mac": "string (MAC address)"
    }
    ```
*   **JSON Schema (Acknowledge Port):**
    ```json
    {
      "mac": "string (MAC address)",
      "port": "integer",
      "protocol": "string (e.g., 'tcp')"
    }
    ```

#### `fortag/scanner/command/set_range`
Updates the default RFC1918 range to scan.

*   **JSON Schema:**
    ```json
    {
      "range": "string (valid RFC1918 IP or CIDR network)"
    }
    ```

MQTT API v2 also accepts an empty `range` string to remove the persisted
override and immediately return to local-interface auto-detection. The scanner
only removes the override after detection produces a valid private IPv4 target;
otherwise it rejects the command and preserves the previous range.

#### `fortag/scanner/command/scan_now`
Triggers an immediate phased network scan.

*   **Payload:** Empty / Null.

### 1.3. MQTT API v2 beta identity and topic namespace

The first beta pair, scanner `1.1.0-rc.1` and Home Assistant integration
`1.1.1b1`, implement MQTT API version `2`. A stable, generated
`scanner_uuid` becomes the canonical topic identity; a new random `instance_id`
identifies each running process. This prepares topic routing and collision
detection but does not add multi-scanner UI support. Home Assistant continues to
support one configured scanner at a time, and multi-scanner aggregation is
unscheduled. The beta components must be upgraded in lockstep; MQTT API v1
frontend/backend combinations are not supported. Existing databases remain
upgradeable through schema version `2`.

The current validation pair is scanner `1.1.0-rc.2` with integration
`1.1.1b2`. It retains MQTT API v2 and adds empty-range auto-detection plus exact
open-port state reconciliation; install the pair together.

Discovery topics:

```text
fortag/discovery/{scanner_uuid}/info
fortag/discovery/{scanner_uuid}/instances/{instance_id}
```

Operational topics:

```text
fortag/scanners/{scanner_uuid}/state
fortag/scanners/{scanner_uuid}/progress
fortag/scanners/{scanner_uuid}/availability
fortag/scanners/{scanner_uuid}/alert
fortag/scanners/{scanner_uuid}/desired/config
fortag/scanners/{scanner_uuid}/reported/config
fortag/scanners/{scanner_uuid}/command/rename_scanner
fortag/scanners/{scanner_uuid}/command/rename
fortag/scanners/{scanner_uuid}/command/acknowledge
fortag/scanners/{scanner_uuid}/command/set_range
fortag/scanners/{scanner_uuid}/command/scan_now
fortag/scanners/{scanner_uuid}/command/result
```

Cancellation will be a separate command from starting a scan, but its final
topic name and the final name of the start command are still open decisions.

Retention is set per published message:

| Message class | Retained | Reason |
| --- | --- | --- |
| Discovery info and instance presence | Yes | New subscribers need identity and ownership state; graceful shutdown deletes presence with a zero-length retained publication. |
| Availability and progress leases | Yes | Home Assistant must detect current, offline, or stale processes. |
| Scanner state | Yes | New subscribers need the latest database snapshot. |
| Desired and reported configuration | Yes | Configuration represents convergent state. |
| Action commands | No | A command must not execute after an unrelated reconnect. |
| Command results and alerts | No | These are correlated events, not durable desired state. |

Every command carries a required UUID `command_id`. The scanner publishes an
immediate `accepted` result followed by exactly one terminal `completed`,
`rejected`, or `failed` result on the shared
`fortag/scanners/{scanner_uuid}/command/result` topic. Results include
`command_id`, the command name, a structured `error_code` when applicable, and a
human-readable `message`. Commands and results use MQTT QoS 1. MQTT delivery acknowledgements do not prove
application processing, so this explicit result reports execution state.

A duplicate means another delivery using a `command_id` the scanner has already
seen; it does not mean two independently identified commands happen to request
the same operation. The scanner keeps a bounded in-memory cache. The same ID and
payload returns the known current or terminal result without executing again;
the same ID with a different payload is rejected with `command_id_conflict`.
Different IDs represent distinct commands. The cache holds at most 1,000 command
IDs and entries expire 24 hours after they were first received. Evicting an
entry means a later reuse of that ID is treated as a new command; the cache does
not survive a scanner restart.

Home Assistant adopts the first scanner registration when no scanner is active,
and the scanner waits for explicit approval before scanning. Home Assistant
receipt order is definitive; lower scanner UUID is the fallback when timestamps
are equal at Home Assistant's available resolution. A scanner observing an
active owner of its UUID generates and persists a replacement UUID. Home
Assistant creates one notification for each additional scanner registration or
adopted-scanner UUID change, reports that the registration was rejected, and
prunes stale instance-presence records after 24 hours.

The balanced timing profile uses a 30-second MQTT keepalive, presence and later
progress heartbeats every 15 seconds, and a 60-second stale threshold. Reconnect
uses equal-jitter exponential backoff from 1 second to a 60-second cap and resets
after two minutes of stable connectivity.

Home Assistant approval is a renewable lease. Loss of MQTT or expiry of approval
prevents a new scan from starting, but an already-running scan may finish locally.
The initial scanner name is the hostname when available, otherwise
`Fortag <short UUID>`, and user changes are persisted in `scanner_identity`.

#### Home Assistant approval lease

Retained discovery and instance-presence messages act as the scanner's
registration request. After adopting a scanner, Home Assistant publishes a
non-retained QoS 1 approval every 15 seconds to:

```text
fortag/scanners/{scanner_uuid}/instances/{instance_id}/approval
```

```json
{
  "scanner_uuid": "8dff77be-651f-49d0-90dd-f9dc1ed7db59",
  "instance_id": "a36c69e4-3432-4c97-b1b4-7085e9d989df",
  "approved": true,
  "lease_seconds": 60,
  "issued_at": "2026-08-22T12:00:00Z"
}
```

The scanner validates both IDs and measures the 60-second lease from local
receipt time; `issued_at` is diagnostic and does not require synchronized
clocks. Retained approval is forbidden. On restart, Home Assistant reads the
adopted UUID from its config entry and automatically resumes approval for that
scanner's current instance. Until a fresh approval arrives, no new scan starts.

#### Schema version 2 scanner identity

MQTT API v2 requires the persistent identity created by this schema migration:

```sql
CREATE TABLE scanner_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    scanner_uuid TEXT NOT NULL UNIQUE,
    scanner_name TEXT NOT NULL,
    previous_uuid TEXT,
    uuid_changed_at DATETIME,
    uuid_change_reason TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

The complete transactional migration and naming rules are defined in
`ARCHITECTURE.md` section 3.

#### Planned recoverable progress payload (post-MQTT-v2 beta)

The later scan-recovery beta extends the retained
`fortag/scanners/{scanner_uuid}/progress` payload:

```json
{
  "scan_id": "UUID",
  "instance_id": "UUID",
  "status": "scanning_hosts",
  "target": "192.168.1.20",
  "target_index": 3,
  "target_total": 12,
  "completed_targets": 2,
  "started_at": "2026-08-22T12:00:00Z",
  "updated_at": "2026-08-22T12:04:15Z"
}
```

Planned statuses are `idle`, `discovering`, `scanning_hosts`, `cancelling`,
`cancelled`, `completed`, `partial`, and `failed`. `target_index` is the
one-based target currently running; `completed_targets` counts only finished
targets. The final cancel/start topics and payloads remain a decision gate for
that later beta.

---

## 2. Home Assistant WebSocket API Reference

The custom component registers WebSocket command handlers mapping to the Home Assistant dashboard frontend.

### 2.1. `fortag_scanner/get_state`
Fetches the cached network scanning state and progress.

*   **Request Format:**
    ```json
    {
      "id": "integer (auto-increment message ID)",
      "type": "fortag_scanner/get_state"
    }
    ```
*   **Response Format:**
    ```json
    {
      "id": "integer",
      "type": "result",
      "success": true,
      "result": {
        "state": {
          "last_scan": "string (RFC3339 timestamp)",
          "duration": "string",
          "hosts": [ ... ]
        },
        "progress": {
          "status": "string",
          "target": "string"
        }
      }
    }
    ```

### 2.2. `fortag_scanner/rename`
Renames a host by publishing an MQTT rename command.

*   **Request Format:**
    ```json
    {
      "id": "integer",
      "type": "fortag_scanner/rename",
      "mac": "string (MAC address)",
      "name": "string (new name)"
    }
    ```

### 2.3. `fortag_scanner/acknowledge`
Acknowledges a host or specific port alert.

*   **Request Format (Host):**
    ```json
    {
      "id": "integer",
      "type": "fortag_scanner/acknowledge",
      "mac": "string (MAC address)"
    }
    ```
*   **Request Format (Port):**
    ```json
    {
      "id": "integer",
      "type": "fortag_scanner/acknowledge",
      "mac": "string (MAC address)",
      "port": "integer",
      "protocol": "string (e.g., 'tcp')"
    }
    ```

### 2.4. `fortag_scanner/set_range`
Updates the scan target subnet range. An empty string enables auto-detection and
removes the persisted override after detection succeeds.

*   **Request Format:**
    ```json
    {
      "id": "integer",
      "type": "fortag_scanner/set_range",
      "range": "string (private IPv4 CIDR/IP, or empty for auto-detection)"
    }
    ```

### 2.5. `fortag_scanner/scan_now`
Triggers a manual network scan.

*   **Request Format:**
    ```json
    {
      "id": "integer",
      "type": "fortag_scanner/scan_now"
    }
    ```
