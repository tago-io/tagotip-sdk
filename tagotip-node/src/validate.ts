import {
  MAX_VARNAME_LEN,
  MAX_SERIAL_LEN,
  MAX_GROUP_LEN,
  MAX_META_KEY_LEN,
  MAX_UNIT_LEN,
} from "./consts.ts";
import { TagotipError, type ParseErrorKind } from "./error.ts";

function fail(kind: ParseErrorKind, pos: number): never {
  throw new TagotipError(kind, pos);
}

function isLowercaseAlnumUnderscore(ch: string): boolean {
  return (
    (ch >= "a" && ch <= "z") ||
    (ch >= "0" && ch <= "9") ||
    ch === "_"
  );
}

export function validateVarname(name: string, pos: number): void {
  if (name.length === 0 || name.length > MAX_VARNAME_LEN) {
    fail("invalid_field", pos);
  }
  for (let i = 0; i < name.length; i++) {
    if (!isLowercaseAlnumUnderscore(name[i])) {
      fail("invalid_field", pos);
    }
  }
}

export function validateSerial(serial: string, pos: number): void {
  if (serial.length === 0 || serial.length > MAX_SERIAL_LEN) {
    fail("invalid_serial", pos);
  }
  for (let i = 0; i < serial.length; i++) {
    const ch = serial[i];
    if (
      !(
        (ch >= "a" && ch <= "z") ||
        (ch >= "A" && ch <= "Z") ||
        (ch >= "0" && ch <= "9") ||
        ch === "-" ||
        ch === "_"
      )
    ) {
      fail("invalid_serial", pos);
    }
  }
}

export function validateGroup(group: string, pos: number): void {
  if (group.length === 0 || group.length > MAX_GROUP_LEN) {
    fail("invalid_field", pos);
  }
  for (let i = 0; i < group.length; i++) {
    if (!isLowercaseAlnumUnderscore(group[i])) {
      fail("invalid_field", pos);
    }
  }
}

export function validateMetaKey(key: string, pos: number): void {
  if (key.length === 0 || key.length > MAX_META_KEY_LEN) {
    fail("invalid_metadata", pos);
  }
  for (let i = 0; i < key.length; i++) {
    if (!isLowercaseAlnumUnderscore(key[i])) {
      fail("invalid_metadata", pos);
    }
  }
}

export function validateUnit(unit: string, pos: number): void {
  if (unit.length === 0 || unit.length > MAX_UNIT_LEN) {
    fail("invalid_field", pos);
  }
}

export function validateNumber(s: string, pos: number): void {
  let i = 0;
  if (i < s.length && s[i] === "-") i++;
  if (i >= s.length) fail("invalid_variable", pos);

  if (s[i] === "0") {
    i++;
  } else if (s[i] >= "1" && s[i] <= "9") {
    i++;
    while (i < s.length && s[i] >= "0" && s[i] <= "9") i++;
  } else {
    fail("invalid_variable", pos);
  }

  if (i < s.length && s[i] === ".") {
    i++;
    if (i >= s.length || s[i] < "0" || s[i] > "9") {
      fail("invalid_variable", pos);
    }
    while (i < s.length && s[i] >= "0" && s[i] <= "9") i++;
  }

  if (i !== s.length) fail("invalid_variable", pos);
}
