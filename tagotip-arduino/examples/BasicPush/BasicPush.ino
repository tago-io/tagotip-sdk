/**
 * BasicPush -- Parse a plaintext PUSH frame and inspect its fields.
 */

#include <string.h>
#include <tagotip.h>

static TagotipUplinkFrame g_frame;

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

static const char *method_name(TagotipMethod method) {
  switch (method) {
    case TAGOTIP_METHOD_PUSH:
      return "PUSH";
    case TAGOTIP_METHOD_PULL:
      return "PULL";
    case TAGOTIP_METHOD_PING:
      return "PING";
  }
  return "UNKNOWN";
}

static const char *operator_name(TagotipOperator op) {
  switch (op) {
    case TAGOTIP_OPERATOR_NUMBER:
      return ":=";
    case TAGOTIP_OPERATOR_STRING:
      return "=";
    case TAGOTIP_OPERATOR_BOOLEAN:
      return "?=";
    case TAGOTIP_OPERATOR_LOCATION:
      return "@=";
  }
  return "?";
}

static void print_value(const TagotipValue *value) {
  if (value == NULL) {
    return;
  }

  switch (value->tag) {
    case TAGOTIP_VALUE_NUMBER:
    case TAGOTIP_VALUE_STRING:
      print_str(&value->str_val);
      break;
    case TAGOTIP_VALUE_BOOLEAN:
      Serial.print(value->bool_val != 0 ? "true" : "false");
      break;
    case TAGOTIP_VALUE_LOCATION:
      print_str(&value->lat);
      Serial.print(",");
      print_str(&value->lng);
      if (value->alt.len > 0) {
        Serial.print(",");
        print_str(&value->alt);
      }
      break;
  }
}

void setup() {
  Serial.begin(115200);
  wait_for_serial();
  Serial.println("TagoTiP Arduino example: BasicPush");

  static const char raw_frame[] =
      "PUSH|4deedd7bab8817ec|sensor-01|[temperature:=32.5#C@1694567890000^reading{source=dht22}]";

  memset(&g_frame, 0, sizeof(g_frame));
  int32_t rc = tagotip_parse_uplink(
      (const uint8_t *)raw_frame, strlen(raw_frame), &g_frame);
  if (rc != TAGOTIP_OK) {
    Serial.print("tagotip_parse_uplink failed: ");
    Serial.println((int)rc);
    return;
  }

  Serial.print("Method: ");
  Serial.println(method_name(g_frame.method));

  Serial.print("Auth: ");
  print_str(&g_frame.auth);
  Serial.println();

  Serial.print("Serial: ");
  print_str(&g_frame.serial);
  Serial.println();

  Serial.print("Variables: ");
  Serial.println((int)g_frame.variables_len);

  if (g_frame.variables_len > 0) {
    const TagotipVariable *v = &g_frame.variables[0];

    Serial.print("First variable: ");
    print_str(&v->name);
    Serial.print(" ");
    Serial.print(operator_name(v->operator_));
    Serial.print(" ");
    print_value(&v->value);
    if (v->unit.len > 0) {
      Serial.print(" #");
      print_str(&v->unit);
    }
    Serial.println();

    if (v->timestamp.len > 0) {
      Serial.print("Timestamp: ");
      print_str(&v->timestamp);
      Serial.println();
    }

    if (v->group.len > 0) {
      Serial.print("Group: ");
      print_str(&v->group);
      Serial.println();
    }
  }
}

void loop() {
  delay(10000);
}
