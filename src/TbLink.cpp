#include "TbLink.h"

#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <mbedtls/sha256.h>

namespace {

// Percent-encode a firmware title/version for safe use as a URL query value.
String urlEncode(const String& value) {
    String encoded;
    char buf[4];
    for (size_t i = 0; i < value.length(); ++i) {
        char c = value[i];
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else {
            snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
            encoded += buf;
        }
    }
    return encoded;
}

// PubSubClient::setCallback() needs a plain function pointer, not a std::function, so
// this trampolines to the one active TbLink instance's handleMessage(). TbLink is
// meant to be instantiated once per device (same assumption every consumer already
// makes about their single ThingsBoard connection).
TbLink* g_instance = nullptr;
void staticCallback(char* topic, uint8_t* payload, unsigned int length) {
    if (g_instance) {
        g_instance->handleMessage(topic, payload, length);
    }
}

}  // namespace

void TbLink::begin(const TbMqttConfig& mqtt, const TbOtaConfig& ota) {
    mqttCfg_ = mqtt;
    otaCfg_ = ota;

    if (mqttCfg_.client_id.isEmpty()) {
        uint8_t mac[6];
        WiFi.macAddress(mac);
        char buf[24];
        snprintf(buf, sizeof(buf), "tblink-%02x%02x%02x", mac[3], mac[4], mac[5]);
        mqttCfg_.client_id = buf;
    }

    if (netLock_ == nullptr) {
        netLock_ = xSemaphoreCreateRecursiveMutex();
    }

    if (mqttCfg_.use_tls) {
        if (mqttCfg_.ca_cert.length() > 0) {
            secureClient_.setCACert(mqttCfg_.ca_cert.c_str());
        } else {
            Serial.println(
                "TbLink: MQTT TLS enabled with no CA cert set - connection is "
                "encrypted but the server identity is NOT verified");
            secureClient_.setInsecure();
        }
        mqttClient_.setClient(secureClient_);
    } else {
        mqttClient_.setClient(plainClient_);
    }

    // PubSubClient::setServer() stores the raw pointer rather than copying the
    // hostname, so it must outlive every call that uses it - mqttCfg_ is a member,
    // stable for this object's lifetime, so this is safe as long as mqttCfg_.host is
    // never reassigned after begin() (it isn't).
    mqttClient_.setServer(mqttCfg_.host.c_str(), mqttCfg_.port);
    mqttClient_.setBufferSize(mqttCfg_.buffer_size);
    mqttClient_.setSocketTimeout(mqttCfg_.socket_timeout_s);

    g_instance = this;
    mqttClient_.setCallback(staticCallback);

    AttributeWatch& otaWatch = attributeWatches_[kOtaWatchIndex];
    otaWatch.active = true;
    otaWatch.keysCsv = "fw_title,fw_version,fw_checksum,fw_checksum_algorithm";
    otaWatch.onComplete = [this](const JsonDocument& merged) { checkOtaAttributes(merged); };

    // Wraparound-safe "fire on the very first loop() check" idiom, same as both
    // source projects use for their own reconnect/heartbeat timers.
    lastReconnectAttempt_ = 0 - mqttCfg_.reconnect_interval_ms;
}

void TbLink::loop() {
    if (otaUpdatePending_) {
        otaUpdatePending_ = false;
        // Deferred here (rather than acted on directly inside the MQTT callback that
        // detected it) because performOtaUpdate() may need to disconnect the MQTT
        // client to free heap for a second TLS session, and that can't safely happen
        // while PubSubClient::loop() is still on the call stack processing the very
        // message that got us here.
        performOtaUpdate(pendingOtaTitle_, pendingOtaVersion_, pendingOtaChecksum_,
                          pendingOtaChecksumAlgorithm_);
        return;
    }

    if (WiFi.status() != WL_CONNECTED) {
        return;
    }

    if (!mqttClient_.connected()) {
        unsigned long now = millis();
        if (now - lastReconnectAttempt_ < mqttCfg_.reconnect_interval_ms) {
            return;
        }
        lastReconnectAttempt_ = now;

        if (mqttCfg_.host.isEmpty() || mqttCfg_.access_token.isEmpty()) {
            return;
        }

        Serial.printf("TbLink: connecting to ThingsBoard at %s:%u...\n",
                       mqttCfg_.host.c_str(), mqttCfg_.port);
        lock();
        bool ok = mqttClient_.connect(mqttCfg_.client_id.c_str(),
                                       mqttCfg_.access_token.c_str(), nullptr);
        unlock();
        if (!ok) {
            Serial.printf("TbLink: connect failed, state=%d\n", mqttClient_.state());
            return;
        }
        onReconnected();
    }

    lock();
    mqttClient_.loop();
    unlock();

    unsigned long now = millis();
    if (now - lastHeartbeat_ >= mqttCfg_.heartbeat_interval_ms) {
        lastHeartbeat_ = now;
        sendTelemetry(mqttCfg_.heartbeat_key.c_str(), true);
    }
}

bool TbLink::connected() { return mqttClient_.connected(); }

void TbLink::onReconnected() {
    Serial.println("TbLink: connected to ThingsBoard");

    lock();
    mqttClient_.subscribe("v1/devices/me/rpc/request/+");
    mqttClient_.subscribe("v1/devices/me/attributes");
    mqttClient_.subscribe("v1/devices/me/attributes/response/+");
    unlock();

    for (size_t i = 0; i < kMaxAttributeWatches; i++) {
        AttributeWatch& watch = attributeWatches_[i];
        if (!watch.active) {
            continue;
        }
        StaticJsonDocument<128> req;
        req["sharedKeys"] = watch.keysCsv;
        char buf[128];
        size_t n = serializeJson(req, buf, sizeof(buf));
        String topic = "v1/devices/me/attributes/request/" + String(i + 1);
        lock();
        mqttClient_.publish(topic.c_str(), (const uint8_t*)buf, n);
        unlock();
    }

    // Fire the heartbeat immediately on this connect rather than waiting a full
    // interval, same wraparound-safe idiom as lastReconnectAttempt_ above.
    lastHeartbeat_ = 0 - mqttCfg_.heartbeat_interval_ms;
}

void TbLink::handleMessage(char* topic, uint8_t* payload, unsigned int length) {
    String topicStr(topic);

    StaticJsonDocument<512> doc;
    DeserializationError err = deserializeJson(doc, payload, length);
    if (err) {
        Serial.print("TbLink: failed to parse incoming JSON: ");
        Serial.println(err.c_str());
        return;
    }

    if (topicStr.startsWith("v1/devices/me/attributes")) {
        handleAttributesMessage(doc);
    } else if (topicStr.startsWith("v1/devices/me/rpc/request/")) {
        handleRpcMessage(topicStr, doc);
    }
}

void TbLink::handleAttributesMessage(const JsonDocument& doc) {
    JsonVariantConst shared = doc["shared"];

    for (size_t i = 0; i < kMaxAttributeWatches; i++) {
        AttributeWatch& watch = attributeWatches_[i];
        if (!watch.active) {
            continue;
        }

        bool updated = false;
        int start = 0;
        while (start < (int)watch.keysCsv.length()) {
            int comma = watch.keysCsv.indexOf(',', start);
            String key = comma < 0 ? watch.keysCsv.substring(start)
                                    : watch.keysCsv.substring(start, comma);
            if (!shared.isNull() && !shared[key].isNull()) {
                watch.cache[key] = shared[key];
                updated = true;
            } else if (!doc[key].isNull()) {
                watch.cache[key] = doc[key];
                updated = true;
            }
            if (comma < 0) {
                break;
            }
            start = comma + 1;
        }

        if (updated && watch.onComplete) {
            watch.onComplete(watch.cache);
        }
    }
}

void TbLink::handleRpcMessage(const String& topic, const JsonDocument& doc) {
    if (!rpcHandler_) {
        return;
    }
    const char* method = doc["method"];
    if (!method) {
        Serial.println("TbLink: RPC message missing 'method' field");
        return;
    }
    JsonVariantConst params = doc["params"];

    StaticJsonDocument<256> response;
    bool handled = rpcHandler_(String(method), params, response);
    if (!handled) {
        return;
    }

    int lastSlash = topic.lastIndexOf('/');
    String requestId = topic.substring(lastSlash + 1);
    String responseTopic = "v1/devices/me/rpc/response/" + requestId;

    char buf[256];
    size_t n = serializeJson(response, buf, sizeof(buf));
    lock();
    mqttClient_.publish(responseTopic.c_str(), (const uint8_t*)buf, n);
    unlock();
}

bool TbLink::requestSharedAttributes(std::initializer_list<const char*> keys,
                                      AttributesHandler onComplete) {
    for (size_t i = kOtaWatchIndex + 1; i < kMaxAttributeWatches; i++) {
        AttributeWatch& watch = attributeWatches_[i];
        if (watch.active) {
            continue;
        }

        watch.active = true;
        watch.keysCsv = "";
        for (const char* k : keys) {
            if (watch.keysCsv.length() > 0) {
                watch.keysCsv += ",";
            }
            watch.keysCsv += k;
        }
        watch.onComplete = onComplete;
        watch.cache.clear();

        // If already connected, request now; otherwise onReconnected() will request
        // it (along with every other active watch) on the next successful connect.
        if (mqttClient_.connected()) {
            StaticJsonDocument<128> req;
            req["sharedKeys"] = watch.keysCsv;
            char buf[128];
            size_t n = serializeJson(req, buf, sizeof(buf));
            String topic = "v1/devices/me/attributes/request/" + String(i + 1);
            lock();
            mqttClient_.publish(topic.c_str(), (const uint8_t*)buf, n);
            unlock();
        }
        return true;
    }
    Serial.println("TbLink: requestSharedAttributes() failed - kMaxAttributeWatches exhausted");
    return false;
}

void TbLink::onRpc(RpcHandler handler) { rpcHandler_ = handler; }
void TbLink::onOtaResult(OtaResultHandler handler) { otaResultHandler_ = handler; }

void TbLink::lock() {
    if (netLock_) {
        xSemaphoreTakeRecursive(netLock_, portMAX_DELAY);
    }
}

void TbLink::unlock() {
    if (netLock_) {
        xSemaphoreGiveRecursive(netLock_);
    }
}

void TbLink::publishJsonDoc(const char* topic, const JsonDocument& doc) {
    char buf[128];
    size_t n = serializeJson(doc, buf, sizeof(buf));
    lock();
    mqttClient_.publish(topic, (const uint8_t*)buf, n);
    unlock();
}

void TbLink::sendTelemetry(const char* key, bool value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/telemetry", doc);
}
void TbLink::sendTelemetry(const char* key, int value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/telemetry", doc);
}
void TbLink::sendTelemetry(const char* key, float value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/telemetry", doc);
}
void TbLink::sendTelemetry(const char* key, const char* value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/telemetry", doc);
}
void TbLink::sendAttribute(const char* key, bool value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/attributes", doc);
}
void TbLink::sendAttribute(const char* key, int value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/attributes", doc);
}
void TbLink::sendAttribute(const char* key, float value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/attributes", doc);
}
void TbLink::sendAttribute(const char* key, const char* value) {
    StaticJsonDocument<128> doc;
    doc[key] = value;
    publishJsonDoc("v1/devices/me/attributes", doc);
}

void TbLink::publishOtaState(const char* state, const char* error) {
    sendAttribute("fw_state", state);
    if (error) {
        sendAttribute("fw_error", error);
    }
}

// ---- OTA ------------------------------------------------------------------------

void TbLink::checkOtaAttributes(const JsonDocument& merged) {
    const char* title = merged["fw_title"] | (const char*)nullptr;
    const char* version = merged["fw_version"] | (const char*)nullptr;
    const char* checksum = merged["fw_checksum"] | (const char*)nullptr;
    const char* checksumAlgorithm = merged["fw_checksum_algorithm"] | (const char*)nullptr;
    if (!title || !version || !checksum || !checksumAlgorithm) {
        return;  // ThingsBoard sends these one at a time after the initial response -
                 // wait until all four have arrived at least once.
    }

    if (otaCfg_.current_fw_version == version) {
        return;  // already on this version
    }

    if (otaCfg_.expected_fw_title.length() > 0 && otaCfg_.expected_fw_title != title) {
        // Not a failure - this package just isn't for this device. Refusing here is
        // what stands in for the ThingsBoard SDK's own title-match refusal, which this
        // raw PubSubClient path doesn't get for free.
        Serial.printf(
            "TbLink: OTA package title '%s' does not match this device's expected "
            "title '%s' - ignoring\n",
            title, otaCfg_.expected_fw_title.c_str());
        return;
    }

    if (otaUpdatePending_) {
        return;  // already queued from an earlier attribute update
    }

    Serial.printf("TbLink: new firmware available - current=%s target=%s\n",
                   otaCfg_.current_fw_version.c_str(), version);
    pendingOtaTitle_ = title;
    pendingOtaVersion_ = version;
    pendingOtaChecksum_ = checksum;
    pendingOtaChecksumAlgorithm_ = checksumAlgorithm;
    otaUpdatePending_ = true;
}

void TbLink::performOtaUpdate(const String& title, const String& version,
                               const String& checksum, const String& checksumAlgorithm) {
    bool useMD5 = checksumAlgorithm.equalsIgnoreCase("MD5");
    bool useSHA256 = checksumAlgorithm.equalsIgnoreCase("SHA256");
    if (!useMD5 && !useSHA256) {
        String err = "unsupported checksum algorithm '" + checksumAlgorithm + "'";
        Serial.println("TbLink: " + err);
        publishOtaState("FAILED", err.c_str());
        if (otaResultHandler_) otaResultHandler_(false, err);
        return;
    }

    publishOtaState("DOWNLOADING");

    String host = otaCfg_.http_host.length() > 0 ? otaCfg_.http_host : mqttCfg_.host;
    String scheme = otaCfg_.force_plain_http ? "http://" : "https://";
    // Always plain HTTP by default: if the OTA host sits behind a Cloudflare Tunnel,
    // its edge triggers a mid-handshake TLS renegotiation that the ESP32's mbedtls
    // client doesn't support, hanging the download until it times out. The firmware
    // binary's integrity is still verified via the checksum delivered over the (TLS,
    // if enabled) MQTT channel, so this only gives up transport confidentiality, not
    // authenticity.
    String url = scheme + host + ":" + String(otaCfg_.http_port) + "/api/v1/" +
                 mqttCfg_.access_token + "/firmware?title=" + urlEncode(title) +
                 "&version=" + urlEncode(version);
    Serial.printf("TbLink: starting OTA update to version %s from: %s\n", version.c_str(),
                  url.c_str());

    // Only relevant when OTA itself needs TLS (force_plain_http == false): ESP32
    // doesn't reliably have enough contiguous heap for two concurrent TLS sessions
    // (MQTT's + OTA's). Not needed in the default plain-HTTP case - there's no second
    // TLS session to make room for.
    if (!otaCfg_.force_plain_http && mqttCfg_.use_tls) {
        lock();
        mqttClient_.disconnect();
        unlock();
    }

    HTTPClient http;
    bool beginOk;
    if (otaCfg_.force_plain_http) {
        beginOk = http.begin(url);
    } else {
        if (otaCfg_.ca_cert.length() > 0) {
            otaSecureClient_.setCACert(otaCfg_.ca_cert.c_str());
        } else {
            Serial.println(
                "TbLink: OTA TLS enabled with no CA cert set - connection is "
                "encrypted but the server identity is NOT verified");
            otaSecureClient_.setInsecure();
        }
        beginOk = http.begin(otaSecureClient_, url);
    }
    if (!beginOk) {
        Serial.println("TbLink: HTTPClient begin() failed");
        publishOtaState("FAILED", "HTTPClient begin() failed");
        if (otaResultHandler_) otaResultHandler_(false, "HTTPClient begin() failed");
        return;
    }

    int httpCode = http.GET();
    if (httpCode != HTTP_CODE_OK) {
        String err = "HTTP GET failed, code " + String(httpCode);
        Serial.println("TbLink: " + err);
        publishOtaState("FAILED", err.c_str());
        if (otaResultHandler_) otaResultHandler_(false, err);
        http.end();
        return;
    }

    int contentLength = http.getSize();
    if (contentLength <= 0) {
        Serial.println("TbLink: invalid content length for firmware binary");
        publishOtaState("FAILED", "invalid content length");
        if (otaResultHandler_) otaResultHandler_(false, "invalid content length");
        http.end();
        return;
    }

    if (!Update.begin(contentLength)) {
        Serial.println("TbLink: not enough flash space to begin OTA update");
        publishOtaState("FAILED", "not enough flash space");
        if (otaResultHandler_) otaResultHandler_(false, "not enough flash space");
        http.end();
        return;
    }

    if (useMD5 && !Update.setMD5(checksum.c_str())) {
        Update.abort();
        Serial.println("TbLink: invalid MD5 checksum string from ThingsBoard");
        publishOtaState("FAILED", "invalid MD5 checksum string");
        if (otaResultHandler_) otaResultHandler_(false, "invalid MD5 checksum string");
        http.end();
        return;
    }

    publishOtaState("DOWNLOADED");

    if (!downloadAndVerifyFirmware(http.getStreamPtr(), contentLength, checksum, useSHA256)) {
        Serial.println("TbLink: firmware download/verification failed");
        publishOtaState("FAILED", "download/verify failed");
        if (otaResultHandler_) otaResultHandler_(false, "download/verify failed");
        http.end();
        return;
    }

    publishOtaState("VERIFIED");

    if (Update.end() && Update.isFinished()) {
        Serial.println("TbLink: OTA update complete and verified! Restarting...");
        publishOtaState("UPDATING");
        if (otaResultHandler_) otaResultHandler_(true, "");
        http.end();
        delay(1000);
        ESP.restart();
    } else {
        String err = String("Update finalize failed: ") + Update.errorString();
        Serial.println("TbLink: " + err);
        publishOtaState("FAILED", err.c_str());
        if (otaResultHandler_) otaResultHandler_(false, err);
        http.end();
    }
}

// Streams the HTTP response body into Update while incrementally hashing it, so a
// multi-hundred-KB firmware image never needs to sit fully in RAM. MD5 is verified by
// Update.end() itself (via the setMD5() call made before writing); SHA256 is verified
// here since Update.h has no built-in SHA256 support.
bool TbLink::downloadAndVerifyFirmware(WiFiClient* stream, int contentLength,
                                        const String& checksum, bool useSha256) {
    uint8_t buf[1024];
    int remaining = contentLength;

    mbedtls_sha256_context shaCtx;
    if (useSha256) {
        mbedtls_sha256_init(&shaCtx);
        mbedtls_sha256_starts_ret(&shaCtx, 0);
    }

    while (remaining > 0) {
        int toRead = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
        int n = stream->readBytes(buf, toRead);
        if (n <= 0) {
            Serial.println("TbLink: OTA stream read failed/timed out");
            if (useSha256) mbedtls_sha256_free(&shaCtx);
            Update.abort();
            return false;
        }
        Update.write(buf, n);
        if (useSha256) mbedtls_sha256_update_ret(&shaCtx, buf, n);
        remaining -= n;
    }

    if (useSha256) {
        uint8_t hash[32];
        mbedtls_sha256_finish_ret(&shaCtx, hash);
        mbedtls_sha256_free(&shaCtx);
        char hex[65];
        for (int i = 0; i < 32; ++i) {
            snprintf(hex + i * 2, 3, "%02x", hash[i]);
        }
        if (!checksum.equalsIgnoreCase(hex)) {
            Serial.printf("TbLink: SHA256 mismatch! expected=%s computed=%s\n",
                          checksum.c_str(), hex);
            Update.abort();
            return false;
        }
        Serial.println("TbLink: SHA256 checksum verified OK");
    }

    return true;
}
