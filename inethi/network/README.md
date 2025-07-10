# Network App API Documentation

This document describes the API endpoints provided by the `network` Django app.

## Endpoints

### 1. Hosts

#### List/Create Hosts

- **URL:** `/api/v1/network/hosts/`
- **Methods:** `GET`, `POST`
- **Description:** List all hosts or create a new host.
- **Query Parameters:**
  - `network_id` (optional): Filter hosts by network.
- **Request Body (POST):**
  - `name`, `ip_address`, `mac_address`, `device_type`, `user`, `radiusdesk_instance`, `cloud`, `realm`, `network`
- **Response:**
  - List of host objects or created host object.

#### Retrieve/Update/Delete Host

- **URL:** `/api/v1/network/hosts/{id}/`
- **Methods:** `GET`, `PUT`, `PATCH`, `DELETE`
- **Description:** Retrieve, update, or delete a specific host by ID.

#### Update Host by Identifier

- **URL:** `/api/v1/network/hosts/update-by-identifier/`
- **Method:** `PUT`
- **Description:** Update a host using identifying fields (mac_address or ip_address + network).
- **Request Body:**
  - `mac_address` (optional)
  - `ip_address` (required if mac_address not provided)
  - `network` (required, network name)
  - Other fields to update
- **Response:**
  - Updated host object.

#### Delete Host by Identifier

- **URL:** `/api/v1/network/hosts/delete-by-identifier/`
- **Method:** `DELETE`
- **Description:** Delete a host using identifying fields (mac_address or ip_address + network).
- **Request Body:**
  - `mac_address` (optional)
  - `ip_address` (required if mac_address not provided)
  - `network` (required, network name)
- **Response:**
  - Success message.

---

### 2. Pings

#### List/Create Pings

- **URL:** `/api/v1/network/pings/`
- **Methods:** `GET`, `POST`
- **Description:** List all ping results or create a new ping.

#### Retrieve/Update/Delete Ping

- **URL:** `/api/v1/network/pings/{id}/`
- **Methods:** `GET`, `PUT`, `PATCH`, `DELETE`
- **Description:** Retrieve, update, or delete a specific ping by ID.

---

### 3. Networks

#### List/Create Networks

- **URL:** `/api/v1/network/networks/`
- **Methods:** `GET`, `POST`
- **Description:** List all networks or create a new network.

#### Retrieve/Update/Delete Network

- **URL:** `/api/v1/network/networks/{id}/`
- **Methods:** `GET`, `PUT`, `PATCH`, `DELETE`
- **Description:** Retrieve, update, or delete a specific network by ID.

#### List Hosts in a Network

- **URL:** `/api/v1/network/networks/{id}/hosts/`
- **Method:** `GET`
- **Description:** List all hosts in the specified network.

---

### 4. Aggregate Ping Data

#### Aggregated Ping Data (Materialized Views)

- **URL:** `/api/v1/network/ping-aggregates/`
- **Method:** `GET`
- **Query Parameters:**
  - `host_ids` (optional): Comma-separated list of host IDs.
  - `aggregation` (optional): One of `15m`, `60m`, `6h`, `12h`, `24h`, `7d`, `30d`, `90d`, `365d`. Default: `15m`.
  - `network_id` (optional): Filter by network.
- **Response:**
  - List of objects: `{ bucket, host_id, uptime_percentage, total_pings }`

#### Aggregated Uptime Data (Per Host)

- **URL:** `/api/v1/network/up-time/`
- **Method:** `GET`
- **Query Parameters:**
  - `period` (optional): Look-back period (e.g., `15 minutes`, `24 hours`).
  - `min_pings` (optional): Minimum number of pings to include a host.
  - `host_ids` (optional): Comma-separated list of host IDs.
  - `network_id` (optional): Filter by network.
- **Response:**
  - List of objects: `{ host_id, uptime_percentage, total_pings }`
  - Hosts with missing or incomplete data are included as offline (uptime 0% or reduced).

#### Device Uptime Line Data

- **URL:** `/api/v1/network/device-uptime/`
- **Method:** `GET`
- **Query Parameters:**
  - `host_id` (required): The device ID.
  - `period` (optional): Look-back period (e.g., `30 minutes`, `1 hour`, `24 hours`). Minimum: `30 minutes`.
  - `network_id` (optional): Filter by network.
- **Response:**
  - List of objects: `{ bucket, uptime_percentage, total_pings }` (5-minute intervals)
  - Missing intervals are filled as offline (uptime 0%).

---

### 5. Ingest Uptime Data

#### Ingest Uptime Data

- **URL:** `/api/v1/network/ingest-uptime/`
- **Method:** `POST`
- **Description:** Ingest ping data from an external source.
- **Request Body:**
  ```json
  {
    "network": <network_id>,
    "network_admin": <network_admin_identifier>,
    "data": [
      { "host": <host_id>, "is_alive": <bool>, "timestamp": <ISO8601 timestamp> },
      ...
    ]
  }
  ```
- **Response:**
  - `{ "created": [<ping_ids>], "errors": [<error_messages>] }`

---

## Notes

- All endpoints require authentication (Keycloak or API key).
- Network admins can only access data for networks they manage.
- Timestamps are in ISO8601 format (UTC, with 'Z' suffix).
- For more details, see the code in `views.py`.
