/**
 * SecureRoundTrip -- TagoTiP/S seal + parse header + open.
 */

#include <string.h>
#include <tagotips.h>

static void wait_for_serial(void) {
  unsigned long start = millis();
  while (!Serial && (millis() - start) < 2000UL) {
  }
}

static const char *method_name(uint8_t method) {
  switch (method) {
    case TAGOTIPS_METHOD_PUSH:
      return "PUSH";
    case TAGOTIPS_METHOD_PULL:
      return "PULL";
    case TAGOTIPS_METHOD_PING:
      return "PING";
    case TAGOTIPS_METHOD_ACK:
      return "ACK";
  }
  return "UNKNOWN";
}

static void print_hex(const uint8_t *data, size_t len) {
  static const char HEX[] = "0123456789abcdef";

  for (size_t i = 0; i < len; i++) {
    uint8_t b = data[i];
    Serial.write(HEX[b >> 4]);
    Serial.write(HEX[b & 0x0f]);
  }
}

void setup() {
  Serial.begin(115200);
  wait_for_serial();
  Serial.println("TagoTiP Arduino example: SecureRoundTrip");

  static const char token[] = "ate2bd319014b24e0a8aca9f00aea4c0d0";
  static const char serial[] = "sensor-01";
  static const uint8_t inner_frame[] = "sensor-01|[temp:=32]";

  uint8_t key[16];
  tagotips_derive_key(token, serial, key, sizeof(key));

  uint8_t auth_hash[8];
  tagotips_derive_auth_hash(token, auth_hash);

  uint8_t device_hash[8];
  tagotips_derive_device_hash(serial, device_hash);

  Serial.print("Auth hash: ");
  print_hex(auth_hash, sizeof(auth_hash));
  Serial.println();
  Serial.print("Device hash: ");
  print_hex(device_hash, sizeof(device_hash));
  Serial.println();

  uint8_t envelope[128];
  int32_t sealed_len = tagotips_seal(
      inner_frame,
      sizeof(inner_frame) - 1,
      TAGOTIPS_METHOD_PUSH,
      42,
      auth_hash,
      device_hash,
      key,
      envelope,
      sizeof(envelope));
  if (sealed_len < 0) {
    Serial.print("tagotips_seal failed: ");
    Serial.println((int)sealed_len);
    return;
  }

  Serial.print("Envelope bytes: ");
  Serial.println((int)sealed_len);
  Serial.print("Envelope hex: ");
  print_hex(envelope, (size_t)sealed_len);
  Serial.println();

  TagotipsHeader parsed_header;
  int32_t header_rc =
      tagotips_parse_header(envelope, (size_t)sealed_len, &parsed_header);
  if (header_rc != TAGOTIPS_OK) {
    Serial.print("tagotips_parse_header failed: ");
    Serial.println((int)header_rc);
    return;
  }

  Serial.print("Header counter: ");
  Serial.println((unsigned long)parsed_header.counter);
  Serial.print("is_envelope: ");
  Serial.println(tagotips_is_envelope(envelope, (size_t)sealed_len));

  TagotipsHeader opened_header;
  uint8_t opened_method = 0;
  uint8_t opened_inner[64];
  int32_t opened_len = tagotips_open(
      envelope,
      (size_t)sealed_len,
      key,
      &opened_header,
      &opened_method,
      opened_inner,
      sizeof(opened_inner));
  if (opened_len < 0) {
    Serial.print("tagotips_open failed: ");
    Serial.println((int)opened_len);
    return;
  }

  Serial.print("Opened method: ");
  Serial.println(method_name(opened_method));
  Serial.print("Opened inner: ");
  Serial.write(opened_inner, (size_t)opened_len);
  Serial.println();
}

void loop() {
  delay(10000);
}
