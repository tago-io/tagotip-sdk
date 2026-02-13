/**
 * BuildPing -- Build and parse a minimal PING uplink frame.
 */

#include <string.h>
#include <tagotip.h>

static TagotipUplinkFrame g_build_frame;
static TagotipUplinkFrame g_parsed_frame;
static uint8_t g_buf[TAGOTIP_ARDUINO_BUF_SIZE];

static void wait_for_serial(void) {
  unsigned long start = millis();
  while (!Serial && (millis() - start) < 2000UL) {
  }
}

static TagotipStr make_str(const char *text) {
  TagotipStr s;
  s.ptr = (const uint8_t *)text;
  s.len = strlen(text);
  return s;
}

static void print_str(const TagotipStr *s) {
  if (s == NULL || s->ptr == NULL || s->len == 0) {
    return;
  }
  Serial.write(s->ptr, s->len);
}

void setup() {
  Serial.begin(115200);
  wait_for_serial();
  Serial.println("TagoTiP Arduino example: BuildPing");

  memset(&g_build_frame, 0, sizeof(g_build_frame));
  g_build_frame.method = TAGOTIP_METHOD_PING;
  g_build_frame.has_seq = 1;
  g_build_frame.seq = 7;
  g_build_frame.auth = make_str("4deedd7bab8817ec");
  g_build_frame.serial = make_str("sensor-01");

  int32_t out_len =
      tagotip_build_uplink(&g_build_frame, g_buf, sizeof(g_buf));
  if (out_len < 0) {
    Serial.print("tagotip_build_uplink failed: ");
    Serial.println((int)out_len);
    return;
  }

  Serial.print("Built uplink (");
  Serial.print((int)out_len);
  Serial.println(" bytes):");
  Serial.write(g_buf, (size_t)out_len);
  Serial.println();

  memset(&g_parsed_frame, 0, sizeof(g_parsed_frame));
  int32_t rc = tagotip_parse_uplink(g_buf, (size_t)out_len, &g_parsed_frame);
  if (rc != TAGOTIP_OK) {
    Serial.print("tagotip_parse_uplink failed: ");
    Serial.println((int)rc);
    return;
  }

  Serial.print("Round-trip seq: ");
  Serial.println((int)g_parsed_frame.seq);
  Serial.print("Round-trip serial: ");
  print_str(&g_parsed_frame.serial);
  Serial.println();
}

void loop() {
  delay(10000);
}
