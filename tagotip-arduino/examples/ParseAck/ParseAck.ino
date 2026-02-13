/**
 * ParseAck -- Parse and inspect an ACK downlink frame.
 */

#include <string.h>
#include <tagotip.h>

static TagotipAckFrame g_ack;

static void wait_for_serial(void) {
  unsigned long start = millis();
  while (!Serial && (millis() - start) < 2000UL) {
  }
}

static void print_str(const TagotipStr *s) {
  if (s == NULL || s->ptr == NULL || s->len == 0) {
    return;
  }
  Serial.write(s->ptr, s->len);
}

static const char *status_name(TagotipAckStatus status) {
  switch (status) {
    case TAGOTIP_ACK_STATUS_OK:
      return "OK";
    case TAGOTIP_ACK_STATUS_PONG:
      return "PONG";
    case TAGOTIP_ACK_STATUS_CMD:
      return "CMD";
    case TAGOTIP_ACK_STATUS_ERR:
      return "ERR";
  }
  return "UNKNOWN";
}

static const char *detail_name(TagotipAckDetailTag tag) {
  switch (tag) {
    case TAGOTIP_ACK_DETAIL_NONE:
      return "NONE";
    case TAGOTIP_ACK_DETAIL_COUNT:
      return "COUNT";
    case TAGOTIP_ACK_DETAIL_VARIABLES:
      return "VARIABLES";
    case TAGOTIP_ACK_DETAIL_COMMAND:
      return "COMMAND";
    case TAGOTIP_ACK_DETAIL_ERROR:
      return "ERROR";
    case TAGOTIP_ACK_DETAIL_RAW:
      return "RAW";
  }
  return "UNKNOWN";
}

void setup() {
  Serial.begin(115200);
  wait_for_serial();
  Serial.println("TagoTiP Arduino example: ParseAck");

  static const char raw_ack[] = "ACK|!12|ERR|invalid_token";

  memset(&g_ack, 0, sizeof(g_ack));
  int32_t rc = tagotip_parse_ack((const uint8_t *)raw_ack, strlen(raw_ack), &g_ack);
  if (rc != TAGOTIP_OK) {
    Serial.print("tagotip_parse_ack failed: ");
    Serial.println((int)rc);
    return;
  }

  if (g_ack.has_seq) {
    Serial.print("Seq: ");
    Serial.println((int)g_ack.seq);
  }

  Serial.print("Status: ");
  Serial.println(status_name(g_ack.status));

  Serial.print("Detail tag: ");
  Serial.println(detail_name(g_ack.detail.tag));

  switch (g_ack.detail.tag) {
    case TAGOTIP_ACK_DETAIL_COUNT:
      Serial.print("Count: ");
      Serial.println((int)g_ack.detail.count);
      break;
    case TAGOTIP_ACK_DETAIL_VARIABLES:
    case TAGOTIP_ACK_DETAIL_COMMAND:
    case TAGOTIP_ACK_DETAIL_RAW:
      Serial.print("Text: ");
      print_str(&g_ack.detail.text);
      Serial.println();
      break;
    case TAGOTIP_ACK_DETAIL_ERROR:
      Serial.print("Error code: ");
      Serial.println((int)g_ack.detail.error_code);
      Serial.print("Error text: ");
      print_str(&g_ack.detail.text);
      Serial.println();
      break;
    case TAGOTIP_ACK_DETAIL_NONE:
      break;
  }
}

void loop() {
  delay(10000);
}
