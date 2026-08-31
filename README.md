# TbLink

Unified ThingsBoard connectivity (MQTT + TLS + Cloudflare-safe OTA + RPC/attributes +
heartbeat) for ESP32/Arduino boards talking to a self-hosted ThingsBoard instance.

Extracted from two real projects — `esp32-mqtt-generic-board` and `ESP32_Alarm_System` —
that independently hit and solved the same problems against the same server. This library
exists so the third project doesn't have to solve them a third time.

## Why not the ThingsBoard C++ SDK?

`esp32-mqtt-generic-board` used it first and it worked well there — but the two projects
have genuinely different device shapes (a generic N-pin board vs. a fixed alarm/relay
layout), and the SDK's compile-time-sized `Server_Side_RPC<N, M>` tables are awkward once
that shape isn't fixed and known at each project's inception. `ESP32_Alarm_System`'s raw
`PubSubClient` + `HTTPClient` approach turned out to be the one already proven against
every hard problem this server has actually produced — most importantly the Cloudflare
Tunnel OTA issue below — so TbLink builds on that instead, and takes over the one thing the
SDK gave up for free (`fw_state`/`fw_error` attribute reporting) so nothing is lost by
skipping it.

## Why OTA is HTTP, and why it's forced to plain HTTP

ThingsBoard's firmware binary is fetched over `GET /api/v1/<token>/firmware`, not over
MQTT. If that host sits behind a Cloudflare Tunnel, HTTPS to it hangs mid-handshake —
Cloudflare's edge triggers a mid-handshake TLS renegotiation that the ESP32's mbedTLS-based
`WiFiClientSecure` doesn't support. Symptom: `start_ssl_client: -1`, the `GET` never
completes, even though the same URL works fine with `curl` from a normal computer.

`TbOtaConfig::force_plain_http` defaults to `true` for this reason. Firmware integrity is
still verified via the MD5/SHA256 checksum delivered as a shared attribute over the (TLS,
if `TbMqttConfig::use_tls`) MQTT channel — going HTTP-only for the binary loses transport
confidentiality, not authenticity. A tampered binary still fails the checksum check and
never gets flashed.

Before ever setting `force_plain_http = false` for a new host, verify with `curl -v`
against both `http://` and `https://` — don't assume a new deployment has the same
Cloudflare topology.

## Why OTA safety needs `expected_fw_title`

The ThingsBoard SDK refuses to apply an update whose `fw_title` doesn't match the
device's own title — which is what stops, e.g., a 30-pin ESP32 binary from ever being
flashed onto an ESP32-S3 board. TbLink doesn't get this for free from PubSubClient, so it
re-implements the check itself: if `TbOtaConfig::expected_fw_title` is set and an assigned
package's `fw_title` doesn't match, TbLink logs and ignores it rather than downloading.
Leave it empty only for a genuinely single-board project where no such mismatch is
possible.

## Why WiFi/AP management isn't in scope

The two source projects' WiFi behavior diverges by deliberate, documented decision, not
just implementation detail: one runs its AP permanently alongside STA
(`WIFI_MODE_APSTA` forever, MAC-derived SSID); the other brings its AP up only as a
fallback once STA has been down for a while (static SSID), and tears it down again once
STA recovers. Forcing one shared WiFi abstraction over that would add real complexity for
no reuse benefit, since neither project's WiFi code is broken. TbLink only checks
`WiFi.status()` itself before doing anything network-related — it never calls
`WiFi.begin()`/`WiFi.softAP()` etc.

## Why a recursive mutex

`lock()`/`unlock()` wrap an internal `SemaphoreHandle_t` created as recursive
(`xSemaphoreCreateRecursiveMutex`). This matters for any project that touches the MQTT
client from a second FreeRTOS task (e.g. a web server on the other core) concurrently with
the task calling `loop()` — a plain (non-recursive) mutex would deadlock the moment a
handler invoked from inside `loop()` (already holding the lock) calls back into
`sendTelemetry()`/`sendAttribute()`, which also lock.

## Why shared-attribute requests are re-issued on every reconnect, not just once

ThingsBoard doesn't reliably push a live update of shared attributes (like a freshly
assigned firmware package) to an already-connected, already-subscribed device — in
testing, a device could sit on stale attribute values indefinitely with zero errors. The
one thing that reliably works is requesting the full set fresh on every new MQTT
connection. `TbLink::onReconnected()` does this automatically for every active
`AttributeWatch` (including the built-in OTA one), so a firmware package assigned while a
device is offline is picked up the moment it reconnects, without needing a periodic
poll — though a project with tighter hands-off-rollout requirements may still want to
force a periodic reconnect (e.g. a scheduled reboot) rather than relying on the device
naturally reconnecting soon.

## Not included (by design)

- WiFi/AP/network management — see above.
- Any opinion on your telemetry/attribute/RPC *schema* beyond the ThingsBoard-standard
  `fw_state`/`fw_error` OTA keys and the one `heartbeat_key` — key names, RPC method
  naming conventions, and payload shapes are entirely up to the consuming project.
