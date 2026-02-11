const ESCAPE_MAP: Record<string, string> = {
  "|": "|",
  "[": "[",
  "]": "]",
  ";": ";",
  ",": ",",
  "{": "{",
  "}": "}",
  "#": "#",
  "@": "@",
  "^": "^",
  "\\": "\\",
  n: "\n",
};

const STRUCTURAL = new Set("|[];,{}#@^\\\n");

export function unescape(s: string): string {
  if (!s.includes("\\")) return s;

  let result = "";
  let i = 0;
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      const next = s[i + 1];
      const decoded = ESCAPE_MAP[next];
      if (decoded !== undefined) {
        result += decoded;
        i += 2;
        continue;
      }
      result += "\\";
      i += 1;
      continue;
    }
    result += s[i];
    i += 1;
  }
  return result;
}

export function escape(s: string): string {
  let result = "";
  for (const ch of s) {
    if (STRUCTURAL.has(ch)) {
      result += "\\";
      result += ch === "\n" ? "n" : ch;
    } else {
      result += ch;
    }
  }
  return result;
}
