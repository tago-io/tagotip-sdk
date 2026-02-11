package tagotip

import "strings"

// escapeMap maps escape characters to their replacement.
var escapeMap = map[byte]byte{
	'|': '|',
	'[': '[',
	']': ']',
	';': ';',
	',': ',',
	'{': '{',
	'}': '}',
	'#': '#',
	'@': '@',
	'^': '^',
	'\\': '\\',
	'n': '\n',
}

// structuralChars is the set of characters that need escaping.
var structuralChars = [256]bool{
	'|':  true,
	'[':  true,
	']':  true,
	';':  true,
	',':  true,
	'{':  true,
	'}':  true,
	'#':  true,
	'@':  true,
	'^':  true,
	'\\': true,
	'\n': true,
}

// reverseEscapeMap maps original bytes to their escape character.
var reverseEscapeMap = map[byte]byte{
	'|':  '|',
	'[':  '[',
	']':  ']',
	';':  ';',
	',':  ',',
	'{':  '{',
	'}':  '}',
	'#':  '#',
	'@':  '@',
	'^':  '^',
	'\\': '\\',
	'\n': 'n',
}

// Unescape replaces TagoTiP escape sequences with their original characters.
func Unescape(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			if ch, ok := escapeMap[s[i+1]]; ok {
				b.WriteByte(ch)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// Escape replaces structural characters with TagoTiP escape sequences.
func Escape(s string) string {
	needsEscape := false
	for i := 0; i < len(s); i++ {
		if structuralChars[s[i]] {
			needsEscape = true
			break
		}
	}
	if !needsEscape {
		return s
	}

	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i++ {
		if esc, ok := reverseEscapeMap[s[i]]; ok {
			b.WriteByte('\\')
			b.WriteByte(esc)
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
