import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Method, Operator, AckStatus, type UplinkFrame } from "../src/index.ts";

describe("types", () => {
  it("should have correct Method enum values", () => {
    assert.equal(Method.Push, "PUSH");
    assert.equal(Method.Pull, "PULL");
    assert.equal(Method.Ping, "PING");
  });

  it("should have correct Operator enum values", () => {
    assert.equal(Operator.Number, "number");
    assert.equal(Operator.String, "string");
    assert.equal(Operator.Boolean, "boolean");
    assert.equal(Operator.Location, "location");
  });

  it("should have correct AckStatus enum values", () => {
    assert.equal(AckStatus.Ok, "OK");
    assert.equal(AckStatus.Pong, "PONG");
    assert.equal(AckStatus.Cmd, "CMD");
    assert.equal(AckStatus.Err, "ERR");
  });

  it("should allow constructing an UplinkFrame object", () => {
    const frame: UplinkFrame = {
      method: Method.Push,
      auth: "at0123456789abcdef0123456789abcdef",
      serial: "my-device",
      pushBody: {
        type: "structured",
        body: {
          variables: [
            {
              name: "temperature",
              operator: Operator.Number,
              value: { type: "number", value: "25.3" },
              unit: "C",
            },
          ],
        },
      },
    };

    assert.equal(frame.method, Method.Push);
    assert.equal(frame.serial, "my-device");
    assert.ok(frame.pushBody);
    assert.equal(frame.pushBody.type, "structured");
  });
});
