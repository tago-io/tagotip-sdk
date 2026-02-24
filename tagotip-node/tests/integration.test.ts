import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseUplink,
  parseAck,
  buildUplink,
  buildAck,
  Method,
  Operator,
  AckStatus,
  ErrorCode,
  PassthroughEncoding,
  TagotipError,
} from "../src/index.ts";
import type { UplinkFrame, AckFrame } from "../src/index.ts";

const AUTH = "4deedd7bab8817ec";

// Helper: parse → build round-trip
function roundtrip(input: string): void {
  const frame = parseUplink(input);
  const output = buildUplink(frame);
  assert.equal(output, input);
}

// =========================================================================
// Parse Uplink — Happy Path
// =========================================================================

describe("parseUplink — happy path", () => {
  it("parse simple push with two variables", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|weather_denver|[temperature:=32;humidity:=65]`
    );
    assert.equal(frame.method, Method.Push);
    assert.equal(frame.serial, "weather_denver");
    assert.equal(frame.auth, AUTH);
    assert.ok(frame.pushBody);
    assert.equal(frame.pushBody!.type, "structured");
    const body = frame.pushBody!.body;
    assert.equal("variables" in body, true);
    if (frame.pushBody!.type === "structured") {
      assert.equal(frame.pushBody!.body.variables.length, 2);
      assert.equal(frame.pushBody!.body.variables[0].name, "temperature");
      assert.equal(frame.pushBody!.body.variables[1].name, "humidity");
    }
  });

  it("parse push with sequence counter", () => {
    const frame = parseUplink(`PUSH|!42|${AUTH}|sensor_01|[temp:=32]`);
    assert.equal(frame.seq, 42);
  });

  it("parse push with number value and unit", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[temperature:=32.5#C]`
    );
    assert.equal(frame.pushBody!.type, "structured");
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      assert.equal(v.operator, Operator.Number);
      assert.equal(v.value.type, "number");
      if (v.value.type === "number") assert.equal(v.value.value, "32.5");
      assert.equal(v.unit, "C");
    }
  });

  it("parse push with string value", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[status=online]`);
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      assert.equal(v.operator, Operator.String);
      assert.equal(v.value.type, "string");
      if (v.value.type === "string") assert.equal(v.value.value, "online");
    }
  });

  it("parse push with boolean true", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[active?=true]`);
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      assert.equal(v.operator, Operator.Boolean);
      assert.equal(v.value.type, "boolean");
      if (v.value.type === "boolean") assert.equal(v.value.value, true);
    }
  });

  it("parse push with boolean false", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[active?=false]`);
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      if (v.value.type === "boolean") assert.equal(v.value.value, false);
    }
  });

  it("parse push with location no altitude", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[pos@=39.74,-104.99]`
    );
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      assert.equal(v.operator, Operator.Location);
      assert.equal(v.value.type, "location");
      if (v.value.type === "location") {
        assert.equal(v.value.value.lat, "39.74");
        assert.equal(v.value.value.lng, "-104.99");
        assert.equal(v.value.value.alt, undefined);
      }
    }
  });

  it("parse push with location and altitude", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[pos@=39.74,-104.99,305]`
    );
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      if (v.value.type === "location") {
        assert.equal(v.value.value.lat, "39.74");
        assert.equal(v.value.value.lng, "-104.99");
        assert.equal(v.value.value.alt, "305");
      }
    }
  });

  it("parse push with negative number", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[temperature:=-15.3]`
    );
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      if (v.value.type === "number") assert.equal(v.value.value, "-15.3");
    }
  });

  it("parse push with metadata", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[temperature:=32{source=dht22}]`
    );
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      assert.ok(v.meta);
      assert.equal(v.meta!.length, 1);
      assert.equal(v.meta![0].key, "source");
      assert.equal(v.meta![0].value, "dht22");
    }
  });

  it("parse push with body-level modifiers", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|@1694567890000^batch_42{firmware=2.1}[temp:=32#C;humidity:=65#%]`
    );
    if (frame.pushBody!.type === "structured") {
      const body = frame.pushBody!.body;
      assert.equal(body.group, "batch_42");
      assert.equal(body.timestamp, "1694567890000");
      assert.ok(body.meta);
      assert.equal(body.meta!.length, 1);
      assert.equal(body.variables.length, 2);
    }
  });

  it("parse push with all suffixes on variable", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[temperature:=32#C@1694567890000^batch_01{source=dht22}]`
    );
    if (frame.pushBody!.type === "structured") {
      const v = frame.pushBody!.body.variables[0];
      assert.equal(v.unit, "C");
      assert.equal(v.timestamp, "1694567890000");
      assert.equal(v.group, "batch_01");
      assert.ok(v.meta);
      assert.equal(v.meta!.length, 1);
    }
  });

  it("parse push passthrough hex", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|>xDEADBEEF01020304`
    );
    assert.ok(frame.pushBody);
    assert.equal(frame.pushBody!.type, "passthrough");
    if (frame.pushBody!.type === "passthrough") {
      assert.equal(frame.pushBody!.body.encoding, PassthroughEncoding.Hex);
      assert.equal(frame.pushBody!.body.data, "DEADBEEF01020304");
    }
  });

  it("parse push passthrough base64", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|>b3q2+7wECAwQ=`);
    if (frame.pushBody!.type === "passthrough") {
      assert.equal(frame.pushBody!.body.encoding, PassthroughEncoding.Base64);
      assert.equal(frame.pushBody!.body.data, "3q2+7wECAwQ=");
    }
  });

  it("parse push datalogger repeated vars", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|datalogger_7|[temp:=32@1694567890000;temp:=33@1694567900000;temp:=31@1694567910000]`
    );
    if (frame.pushBody!.type === "structured") {
      const vars = frame.pushBody!.body.variables;
      assert.equal(vars.length, 3);
      assert.equal(vars[0].name, "temp");
      assert.equal(vars[1].name, "temp");
      assert.equal(vars[2].name, "temp");
    }
  });

  it("parse pull single variable", () => {
    const frame = parseUplink(
      `PULL|${AUTH}|weather_denver|[temperature]`
    );
    assert.equal(frame.method, Method.Pull);
    assert.ok(frame.pullBody);
    assert.equal(frame.pullBody!.variables.length, 1);
    assert.equal(frame.pullBody!.variables[0], "temperature");
  });

  it("parse pull multiple variables", () => {
    const frame = parseUplink(
      `PULL|${AUTH}|weather_denver|[temperature;humidity;pressure]`
    );
    assert.ok(frame.pullBody);
    assert.equal(frame.pullBody!.variables.length, 3);
  });

  it("parse ping", () => {
    const frame = parseUplink(`PING|${AUTH}|sensor_01`);
    assert.equal(frame.method, Method.Ping);
    assert.equal(frame.pushBody, undefined);
    assert.equal(frame.pullBody, undefined);
  });

  it("trailing newline accepted", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[temp:=32]\n`);
    assert.equal(frame.method, Method.Push);
  });
});

// =========================================================================
// Parse Uplink — Error Cases
// =========================================================================

describe("parseUplink — error cases", () => {
  it("rejects empty string", () => {
    assert.throws(() => parseUplink(""), TagotipError);
  });

  it("rejects invalid method", () => {
    assert.throws(
      () => parseUplink(`INVALID|${AUTH}|sensor_01|[temp:=32]`),
      TagotipError
    );
  });

  it("rejects invalid auth token", () => {
    assert.throws(
      () => parseUplink(`PUSH|badauth|sensor_01|[temp:=32]`),
      TagotipError
    );
  });

  it("rejects missing serial", () => {
    assert.throws(() => parseUplink(`PUSH|${AUTH}`), TagotipError);
  });

  it("rejects missing body for PUSH", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01`),
      TagotipError
    );
  });

  it("rejects missing body for PULL", () => {
    assert.throws(
      () => parseUplink(`PULL|${AUTH}|sensor_01`),
      TagotipError
    );
  });

  it("rejects empty variable block", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[]`),
      TagotipError
    );
  });

  it("rejects invalid boolean", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[active?=yes]`),
      TagotipError
    );
  });

  it("rejects leading zero number", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=032]`),
      TagotipError
    );
  });

  it("rejects odd hex passthrough", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|>xABC`),
      TagotipError
    );
  });

  it("rejects frame too large", () => {
    const bigValue = "x".repeat(16385);
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[msg=${bigValue}]`),
      TagotipError
    );
  });

  it("rejects NUL byte", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor\x0001|[temp:=32]`),
      TagotipError
    );
  });

  it("rejects empty string value", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[status=]`),
      TagotipError
    );
  });

  it("rejects trailing dot in number", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=5.]`),
      TagotipError
    );
  });

  it("rejects dot-only number", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=.5]`),
      TagotipError
    );
  });

  it("rejects location with unit", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[pos@=39.74,-104.99#m]`),
      TagotipError
    );
  });

  it("rejects empty metadata block", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[temp:=32{}]`),
      TagotipError
    );
  });

  it("rejects metadata missing equals", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[temp:=32{keyonly}]`),
      TagotipError
    );
  });

  it("rejects body group before timestamp", () => {
    assert.throws(
      () =>
        parseUplink(
          `PUSH|${AUTH}|sensor_01|^group_01@1694567890000[temp:=32]`
        ),
      TagotipError
    );
  });

  it("rejects location with 4 components", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[pos@=1,2,3,4]`),
      TagotipError
    );
  });

  it("rejects seq with leading zeros", () => {
    assert.throws(
      () => parseUplink(`PUSH|!01|${AUTH}|sensor_01|[temp:=32]`),
      TagotipError
    );
  });

  it("rejects empty seq", () => {
    assert.throws(
      () => parseUplink(`PUSH|!|${AUTH}|sensor_01|[temp:=32]`),
      TagotipError
    );
  });

  it("rejects negative seq", () => {
    assert.throws(
      () => parseUplink(`PUSH|!-1|${AUTH}|sensor_01|[temp:=32]`),
      TagotipError
    );
  });

  it("rejects auth too short", () => {
    assert.throws(
      () =>
        parseUplink(
          `PUSH|4deedd7bab8817e|sensor_01|[temp:=32]`
        ),
      TagotipError
    );
  });

  it("rejects auth non-hex", () => {
    assert.throws(
      () =>
        parseUplink(
          `PUSH|4deedd7bab8817gz|sensor_01|[temp:=32]`
        ),
      TagotipError
    );
  });

  it("rejects empty number value", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=]`),
      TagotipError
    );
  });

  it("rejects alpha number value", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=abc]`),
      TagotipError
    );
  });

  it("rejects location empty lat", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[pos@=,-104.99]`),
      TagotipError
    );
  });

  it("rejects location empty lng", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[pos@=39.74,]`),
      TagotipError
    );
  });

  it("rejects location empty alt", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[pos@=39.74,-104.99,]`),
      TagotipError
    );
  });
});

// =========================================================================
// Parse ACK
// =========================================================================

describe("parseAck", () => {
  it("parse ack ok with count", () => {
    const frame = parseAck("ACK|OK|3");
    assert.equal(frame.status, AckStatus.Ok);
    assert.ok(frame.detail);
    assert.equal(frame.detail!.type, "count");
    if (frame.detail!.type === "count") assert.equal(frame.detail!.count, 3);
  });

  it("parse ack ok with zero count", () => {
    const frame = parseAck("ACK|OK|0");
    assert.equal(frame.detail?.type, "count");
    if (frame.detail?.type === "count") assert.equal(frame.detail.count, 0);
  });

  it("parse ack ok with variables", () => {
    const frame = parseAck("ACK|OK|[temperature:=32#F@1694567890000]");
    assert.equal(frame.status, AckStatus.Ok);
    assert.ok(frame.detail);
    assert.equal(frame.detail!.type, "variables");
  });

  it("parse ack ok no detail", () => {
    const frame = parseAck("ACK|OK");
    assert.equal(frame.status, AckStatus.Ok);
    assert.equal(frame.detail, undefined);
  });

  it("parse ack pong", () => {
    const frame = parseAck("ACK|PONG");
    assert.equal(frame.status, AckStatus.Pong);
    assert.equal(frame.detail, undefined);
  });

  it("parse ack cmd", () => {
    const frame = parseAck("ACK|CMD|reboot");
    assert.equal(frame.status, AckStatus.Cmd);
    assert.ok(frame.detail);
    assert.equal(frame.detail!.type, "command");
    if (frame.detail!.type === "command")
      assert.equal(frame.detail!.command, "reboot");
  });

  it("parse ack cmd with value", () => {
    const frame = parseAck("ACK|CMD|ota=https://example.com/v2.1.bin");
    assert.equal(frame.detail?.type, "command");
    if (frame.detail?.type === "command")
      assert.equal(
        frame.detail.command,
        "ota=https://example.com/v2.1.bin"
      );
  });

  it("parse ack cmd no detail", () => {
    const frame = parseAck("ACK|CMD");
    assert.equal(frame.status, AckStatus.Cmd);
    assert.equal(frame.detail, undefined);
  });

  it("parse ack err invalid_token", () => {
    const frame = parseAck("ACK|ERR|invalid_token");
    assert.equal(frame.status, AckStatus.Err);
    assert.ok(frame.detail);
    assert.equal(frame.detail!.type, "error");
    if (frame.detail!.type === "error")
      assert.equal(frame.detail!.code, ErrorCode.InvalidToken);
  });

  it("parse ack err all error codes", () => {
    const codes = [
      ["invalid_token", ErrorCode.InvalidToken],
      ["invalid_method", ErrorCode.InvalidMethod],
      ["invalid_payload", ErrorCode.InvalidPayload],
      ["invalid_seq", ErrorCode.InvalidSeq],
      ["device_not_found", ErrorCode.DeviceNotFound],
      ["variable_not_found", ErrorCode.VariableNotFound],
      ["rate_limited", ErrorCode.RateLimited],
      ["auth_failed", ErrorCode.AuthFailed],
      ["unsupported_version", ErrorCode.UnsupportedVersion],
      ["payload_too_large", ErrorCode.PayloadTooLarge],
      ["server_error", ErrorCode.ServerError],
    ] as const;

    for (const [text, expected] of codes) {
      const frame = parseAck(`ACK|ERR|${text}`);
      assert.equal(frame.detail?.type, "error", `failed for: ${text}`);
      if (frame.detail?.type === "error")
        assert.equal(frame.detail.code, expected, `wrong code for: ${text}`);
    }
  });

  it("parse ack unknown error code", () => {
    const frame = parseAck("ACK|ERR|some_future_error");
    if (frame.detail?.type === "error") {
      assert.equal(frame.detail.code, ErrorCode.Unknown);
      assert.equal(frame.detail.text, "some_future_error");
    }
  });

  it("parse ack with sequence counter", () => {
    const frame = parseAck("ACK|!1|OK|2");
    assert.equal(frame.seq, 1);
    assert.equal(frame.status, AckStatus.Ok);
  });

  it("parse ack trailing newline", () => {
    const frame = parseAck("ACK|OK|3\n");
    assert.ok(frame.detail);
    assert.equal(frame.detail?.type, "count");
    if (frame.detail?.type === "count") assert.equal(frame.detail.count, 3);
  });

  it("parse ack ok large count", () => {
    const frame = parseAck("ACK|OK|4294967295");
    if (frame.detail?.type === "count")
      assert.equal(frame.detail.count, 4294967295);
  });

  it("rejects empty ack", () => {
    assert.throws(() => parseAck("ACK"), TagotipError);
  });

  it("rejects invalid ack status", () => {
    assert.throws(() => parseAck("ACK|UNKNOWN"), TagotipError);
  });
});

// =========================================================================
// Build + Round-trip
// =========================================================================

describe("buildUplink — round-trip", () => {
  it("round-trip simple push", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[temperature:=32;humidity:=65]`);
  });

  it("round-trip push with seq", () => {
    roundtrip(`PUSH|!1|${AUTH}|sensor_01|[temp:=32]`);
  });

  it("round-trip push with unit", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[temperature:=32#C]`);
  });

  it("round-trip push with all suffixes", () => {
    roundtrip(
      `PUSH|${AUTH}|sensor_01|[temperature:=32#C@1694567890000^batch_01{source=dht22}]`
    );
  });

  it("round-trip push boolean", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[active?=true]`);
    roundtrip(`PUSH|${AUTH}|sensor_01|[active?=false]`);
  });

  it("round-trip push location no alt", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[pos@=39.74,-104.99]`);
  });

  it("round-trip push location with alt", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[pos@=39.74,-104.99,305]`);
  });

  it("round-trip push string with escape", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[msg=hello\\|world]`);
  });

  it("round-trip push passthrough hex", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|>xDEADBEEF01020304`);
  });

  it("round-trip push passthrough base64", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|>b3q2+7wECAwQ=`);
  });

  it("round-trip push body modifiers", () => {
    roundtrip(
      `PUSH|${AUTH}|sensor_01|@1694567890000^group_01{firmware=2.1}[temp:=32]`
    );
  });

  it("round-trip pull", () => {
    const input = `PULL|${AUTH}|sensor_01|[temperature;humidity]`;
    const frame = parseUplink(input);
    const output = buildUplink(frame);
    assert.equal(output, input);
  });

  it("round-trip ping", () => {
    const input = `PING|${AUTH}|sensor_01`;
    const frame = parseUplink(input);
    const output = buildUplink(frame);
    assert.equal(output, input);
  });
});

describe("buildAck — round-trip", () => {
  it("round-trip ack ok with count", () => {
    const input = "ACK|OK|3";
    const frame = parseAck(input);
    assert.equal(buildAck(frame), input);
  });

  it("round-trip ack with seq", () => {
    const input = "ACK|!1|OK|2";
    const frame = parseAck(input);
    assert.equal(buildAck(frame), input);
  });

  it("round-trip ack pong", () => {
    const input = "ACK|PONG";
    const frame = parseAck(input);
    assert.equal(buildAck(frame), input);
  });

  it("round-trip ack cmd", () => {
    const input = "ACK|CMD|reboot";
    const frame = parseAck(input);
    assert.equal(buildAck(frame), input);
  });

  it("round-trip ack err all codes", () => {
    const codes = [
      "invalid_token",
      "invalid_method",
      "invalid_payload",
      "invalid_seq",
      "device_not_found",
      "variable_not_found",
      "rate_limited",
      "auth_failed",
      "unsupported_version",
      "payload_too_large",
      "server_error",
    ];
    for (const code of codes) {
      const input = `ACK|ERR|${code}`;
      const frame = parseAck(input);
      assert.equal(buildAck(frame), input, `round-trip failed for: ${code}`);
    }
  });
});

// =========================================================================
// Spec §11 Examples
// =========================================================================

describe("spec §11 examples", () => {
  it("§11.1 simple push", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|weather_denver|[temperature:=32;humidity:=65]`
    );
    assert.equal(frame.method, Method.Push);
    if (frame.pushBody?.type === "structured")
      assert.equal(frame.pushBody.body.variables.length, 2);
  });

  it("§11.2 push with seq", () => {
    const frame = parseUplink(
      `PUSH|!1|${AUTH}|weather_denver|[temperature:=32;humidity:=65]`
    );
    assert.equal(frame.seq, 1);
  });

  it("§11.3 typed values", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_0a1f|[temperature:=32.5#C;status=online;active?=true]`
    );
    if (frame.pushBody?.type === "structured") {
      const vars = frame.pushBody.body.variables;
      assert.equal(vars[0].operator, Operator.Number);
      assert.equal(vars[1].operator, Operator.String);
      assert.equal(vars[2].operator, Operator.Boolean);
    }
  });

  it("§11.3 negative number", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_0a1f|[temperature:=-15.3#C]`
    );
    if (frame.pushBody?.type === "structured") {
      const v = frame.pushBody.body.variables[0];
      if (v.value.type === "number") assert.equal(v.value.value, "-15.3");
    }
  });

  it("§11.4 location", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|drone_07|[altitude:=305#m;position@=39.74,-104.99,305]`
    );
    if (frame.pushBody?.type === "structured")
      assert.equal(
        frame.pushBody.body.variables[1].operator,
        Operator.Location
      );
  });

  it("§11.5 metadata", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[temperature:=32{source=dht22,quality=high}]`
    );
    if (frame.pushBody?.type === "structured") {
      const v = frame.pushBody.body.variables[0];
      assert.ok(v.meta);
      assert.equal(v.meta!.length, 2);
    }
  });

  it("§11.6 body-level defaults", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|@1694567890000^batch_42{firmware=2.1}[temperature:=32#C;humidity:=65#%]`
    );
    if (frame.pushBody?.type === "structured") {
      const body = frame.pushBody.body;
      assert.equal(body.group, "batch_42");
      assert.equal(body.timestamp, "1694567890000");
    }
  });

  it("§11.7 datalogger", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|datalogger_7|[temp:=32@1694567890000;temp:=33@1694567900000;temp:=31@1694567910000]`
    );
    if (frame.pushBody?.type === "structured")
      assert.equal(frame.pushBody.body.variables.length, 3);
  });

  it("§11.8 hex passthrough", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|>xDEADBEEF01020304`
    );
    assert.equal(frame.pushBody?.type, "passthrough");
  });

  it("§11.9 base64 passthrough", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|>b3q2+7wECAwQ=`);
    assert.equal(frame.pushBody?.type, "passthrough");
  });

  it("§11.10 pull", () => {
    const frame = parseUplink(
      `PULL|${AUTH}|weather_denver|[temperature]`
    );
    assert.equal(frame.method, Method.Pull);
    assert.ok(frame.pullBody);
  });

  it("§11.12 ping", () => {
    const frame = parseUplink(`PING|${AUTH}|sensor_01`);
    assert.equal(frame.method, Method.Ping);
  });
});

// =========================================================================
// Number Edge Cases
// =========================================================================

describe("number edge cases", () => {
  it("accepts zero", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[n:=0]`);
    if (frame.pushBody?.type === "structured")
      if (frame.pushBody.body.variables[0].value.type === "number")
        assert.equal(frame.pushBody.body.variables[0].value.value, "0");
  });

  it("accepts negative zero", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[n:=-0]`);
    if (frame.pushBody?.type === "structured")
      if (frame.pushBody.body.variables[0].value.type === "number")
        assert.equal(frame.pushBody.body.variables[0].value.value, "-0");
  });

  it("accepts decimal", () => {
    const frame = parseUplink(`PUSH|${AUTH}|sensor_01|[n:=3.14]`);
    if (frame.pushBody?.type === "structured")
      if (frame.pushBody.body.variables[0].value.type === "number")
        assert.equal(frame.pushBody.body.variables[0].value.value, "3.14");
  });

  it("accepts 0.5", () => {
    roundtrip(`PUSH|${AUTH}|sensor_01|[n:=0.5]`);
  });

  it("accepts large integer", () => {
    const frame = parseUplink(
      `PUSH|${AUTH}|sensor_01|[n:=999999999999]`
    );
    if (frame.pushBody?.type === "structured")
      if (frame.pushBody.body.variables[0].value.type === "number")
        assert.equal(
          frame.pushBody.body.variables[0].value.value,
          "999999999999"
        );
  });

  it("rejects negative leading zero", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=-032]`),
      TagotipError
    );
  });

  it("rejects double negative", () => {
    assert.throws(
      () => parseUplink(`PUSH|${AUTH}|sensor_01|[n:=--5]`),
      TagotipError
    );
  });
});

// =========================================================================
// Seq Edge Cases
// =========================================================================

describe("seq edge cases", () => {
  it("accepts zero", () => {
    const frame = parseUplink(
      `PUSH|!0|${AUTH}|sensor_01|[temp:=32]`
    );
    assert.equal(frame.seq, 0);
  });

  it("accepts max u32", () => {
    const frame = parseUplink(
      `PUSH|!4294967295|${AUTH}|sensor_01|[temp:=32]`
    );
    assert.equal(frame.seq, 4294967295);
  });

  it("rejects overflow", () => {
    assert.throws(
      () =>
        parseUplink(`PUSH|!4294967296|${AUTH}|sensor_01|[temp:=32]`),
      TagotipError
    );
  });
});
