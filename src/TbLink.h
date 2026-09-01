// TbLink — unified ThingsBoard connectivity for ESP32/Arduino boards talking to a
// self-hosted, Cloudflare-fronted ThingsBoard instance.
//
// Built on PubSubClient + HTTPClient, deliberately not the ThingsBoard C++ SDK: every
// project so far has a different device shape (generic N-pin board vs. a fixed
// alarm/relay layout), and the SDK's compile-time-sized RPC tables buy little over a
// few lines of ArduinoJson while adding a second library dependency to track. See
// README.md for the full design rationale.
//
// Scope is deliberately narrow: MQTT connection + TLS, Cloudflare-safe OTA, RPC
// dispatch, shared-attribute request/cache, and a liveness heartbeat. WiFi/AP
// management is NOT included — it varies by real, deliberate per-project decisions
// (always-on AP vs. fallback-only AP, static vs. MAC-derived SSID) that don't
// generalize, and neither existing project's WiFi code needs replacing. TbLink just
// checks WiFi.status() itself before doing anything network-related.
//
// Thread safety: all public methods lock an internal recursive mutex, so TbLink is
// safe to call from a second FreeRTOS task (e.g. a web server) concurrently with the
// task calling loop(). The mutex is recursive so a handler invoked synchronously from
// inside loop() (already holding the lock) can still call back into sendTelemetry()
// etc. without deadlocking.

#pragma once

#include <Arduino.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <functional>
#include <initializer_list>

struct TbMqttConfig {
    String host;                     // MQTT broker host. May need to be a DNS-only
                                      // subdomain if your main domain is
                                      // Cloudflare-proxied — the proxy won't forward
                                      // arbitrary TCP (e.g. 8883), only HTTP(S) ports.
    uint16_t port = 1883;
    String access_token;
    String client_id;                // must be unique per device; if empty, TbLink
                                      // derives one from the chip's MAC address
    bool use_tls = false;
    String ca_cert;                  // empty => WiFiClientSecure::setInsecure()
                                      // (encrypted, NOT authenticated — TbLink logs
                                      // this loudly, never silently)
    uint16_t socket_timeout_s = 3;   // PubSubClient's default is 15s; a stuck
                                      // client.connect() blocks the entire
                                      // single-threaded loop (and anything sharing a
                                      // core with it) for that long
    uint16_t buffer_size = 512;      // PubSubClient's default (256B) silently
                                      // truncates larger telemetry/RPC payloads
    unsigned long reconnect_interval_ms = 10000;  // each attempt can itself block for
                                      // socket_timeout_s — don't retry every loop tick
    unsigned long heartbeat_interval_ms = 8000;   // periodic liveness telemetry;
                                      // client-side offline-staleness thresholds
                                      // downstream should be roughly 3x this
    String heartbeat_key = "heartbeat";
};

struct TbOtaConfig {
    String http_host;                // OTA/REST host; falls back to mqtt.host if
                                      // empty. Can differ from the MQTT host (e.g. a
                                      // Cloudflare-proxied REST API vs. a DNS-only
                                      // MQTT subdomain) — hence its own CA cert below.
    uint16_t http_port = 8080;
    String ca_cert;                  // only used when force_plain_http is false
    bool force_plain_http = true;    // if http_host sits behind a Cloudflare Tunnel,
                                      // HTTPS OTA hangs mid-handshake (mbedTLS can't
                                      // do Cloudflare's renegotiation). Verify with
                                      // `curl -v` against both schemes on a new host
                                      // before ever setting this false.
    String current_fw_version;       // compared to the assigned version by EXACT
                                      // string equality — must match ThingsBoard's
                                      // package version string byte-for-byte,
                                      // including any prefix and case
    String current_fw_title;         // published as-is (see below) - purely
                                      // informational, not compared against anything
    String expected_fw_title;        // if non-empty, an assigned package whose
                                      // fw_title doesn't match this is silently
                                      // ignored (logged, not downloaded) rather than
                                      // flashed — the safety net that stops e.g. a
                                      // 30-pin binary from ever being pushed to an
                                      // S3 board. Leave empty only for a single-board
                                      // project where no such mismatch is possible.
};

class TbLink {
public:
    // method, params -> handled? Fill `response` only when handled==true and a reply
    // should be published (leave it empty to publish an empty `{}` ack, or just don't
    // bother filling it for a one-way RPC call that isn't listening for one anyway).
    using RpcHandler = std::function<bool(const String& method, JsonVariantConst params,
                                           JsonDocument& response)>;

    // Fired after every OTA attempt, in addition to (not instead of) TbLink
    // publishing the standard `fw_state`/`fw_error` client attributes itself — this
    // handler is purely for your own app-level status telemetry, so TbLink still has
    // no opinion on that schema.
    using OtaResultHandler = std::function<void(bool success, const String& error)>;

    // Called every time an incoming attribute message updates at least one of the
    // watched keys — not just once when all are present. `merged` accumulates values
    // across calls (ThingsBoard sends the full requested set together only in the
    // one-time startup response; after that, live pushes send one changed key at a
    // time), so check `merged["key"].isNull()` for completeness rather than assuming
    // every call has everything.
    using AttributesHandler = std::function<void(const JsonDocument& merged)>;

    void begin(const TbMqttConfig& mqtt, const TbOtaConfig& ota);

    // Call every loop() iteration. Non-blocking except for the bounded
    // socket_timeout_s window during a (rate-limited) reconnect attempt, and for the
    // duration of an in-progress OTA download.
    void loop();

    bool connected();

    void sendTelemetry(const char* key, bool value);
    void sendTelemetry(const char* key, int value);
    void sendTelemetry(const char* key, float value);
    void sendTelemetry(const char* key, const char* value);
    void sendAttribute(const char* key, bool value);
    void sendAttribute(const char* key, int value);
    void sendAttribute(const char* key, float value);
    void sendAttribute(const char* key, const char* value);

    // Requests the given shared attribute keys and watches for both the one-time
    // response and any future live update to them, for the life of this TbLink
    // instance (re-requested automatically on every reconnect, same as TbLink's own
    // internal fw_* watch used for OTA). Up to kMaxAttributeWatches concurrent watches
    // (including the built-in OTA one) — returns false if that's exhausted.
    static constexpr size_t kMaxAttributeWatches = 4;
    bool requestSharedAttributes(std::initializer_list<const char*> keys,
                                  AttributesHandler onComplete);

    void onRpc(RpcHandler handler);
    void onOtaResult(OtaResultHandler handler);

    // For app code that needs to publish outside TbLink's own helpers (e.g. a web
    // server task touching shared state). TbLink's own methods already take this
    // internally.
    void lock();
    void unlock();

    // Internal use only — the PubSubClient callback trampoline (a free function, since
    // PubSubClient::setCallback needs a plain function pointer) calls this. Not part of
    // the public API contract; don't call it from app code.
    void handleMessage(char* topic, uint8_t* payload, unsigned int length);

private:
    struct AttributeWatch {
        bool active = false;
        String keysCsv;
        StaticJsonDocument<512> cache;
        AttributesHandler onComplete;
    };

    void handleAttributesMessage(const JsonDocument& doc);
    void handleRpcMessage(const String& topic, const JsonDocument& doc);
    void onReconnected();
    void checkOtaAttributes(const JsonDocument& merged);
    void performOtaUpdate(const String& title, const String& version,
                           const String& checksum, const String& checksumAlgorithm);
    bool downloadAndVerifyFirmware(WiFiClient* stream, int contentLength,
                                    const String& checksum, bool useSha256);
    void publishOtaState(const char* state, const char* error = nullptr);
    void publishJsonDoc(const char* topic, const JsonDocument& doc);

    TbMqttConfig mqttCfg_;
    TbOtaConfig otaCfg_;

    WiFiClient plainClient_;
    WiFiClientSecure secureClient_;
    WiFiClientSecure otaSecureClient_;  // only used when otaCfg_.force_plain_http == false
    PubSubClient mqttClient_{plainClient_};

    SemaphoreHandle_t netLock_ = nullptr;

    unsigned long lastReconnectAttempt_ = 0;
    unsigned long lastHeartbeat_ = 0;

    AttributeWatch attributeWatches_[kMaxAttributeWatches];
    static constexpr size_t kOtaWatchIndex = 0;  // reserved at begin()

    RpcHandler rpcHandler_;
    OtaResultHandler otaResultHandler_;

    volatile bool otaUpdatePending_ = false;
    String pendingOtaTitle_, pendingOtaVersion_, pendingOtaChecksum_, pendingOtaChecksumAlgorithm_;
};
