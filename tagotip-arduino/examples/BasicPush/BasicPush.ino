/**
 * BasicPush — Minimal TagoTiP PUSH frame example.
 *
 * Demonstrates building a PUSH frame with a single variable
 * using the TagoTiP codec library.
 */

#include <tagotip.h>

void setup() {
    Serial.begin(115200);

    // Example: build a simple PUSH frame with one variable.
    // In a real application, you would populate the frame struct
    // from sensor readings and call tagotip_build_uplink().

    uint8_t buf[TAGOTIP_ARDUINO_BUF_SIZE];

    // TODO: Populate TagotipUplinkFrame and call tagotip_build_uplink().
    // For now, just print a placeholder message.
    Serial.println("TagoTiP BasicPush example");
    Serial.print("Buffer size: ");
    Serial.println(TAGOTIP_ARDUINO_BUF_SIZE);
}

void loop() {
    // Nothing to do in loop for this example.
    delay(10000);
}
