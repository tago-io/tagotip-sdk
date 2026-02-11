package tagotip

import "strings"

const maxFields = 8

// ---------------------------------------------------------------------------
// Field splitting
// ---------------------------------------------------------------------------

func splitFields(input string) []string {
	fields := make([]string, 0, 5)
	start := 0
	i := 0
	for i < len(input) {
		if input[i] == '\\' && i+1 < len(input) {
			i += 2
			continue
		}
		if input[i] == '|' {
			fields = append(fields, input[start:i])
			start = i + 1
			if len(fields) == maxFields-1 {
				fields = append(fields, input[start:])
				return fields
			}
		}
		i++
	}
	fields = append(fields, input[start:])
	return fields
}

// ---------------------------------------------------------------------------
// Helper parsers
// ---------------------------------------------------------------------------

func parseMethod(s string) (Method, error) {
	switch s {
	case "PUSH":
		return MethodPush, nil
	case "PULL":
		return MethodPull, nil
	case "PING":
		return MethodPing, nil
	default:
		return 0, fail(ErrInvalidMethod, 0)
	}
}

func parseSeq(s string, pos int) (uint32, error) {
	if len(s) == 0 || s[0] != '!' {
		return 0, fail(ErrInvalidSeq, pos)
	}
	numStr := s[1:]
	if len(numStr) == 0 {
		return 0, fail(ErrInvalidSeq, pos)
	}
	if len(numStr) > 1 && numStr[0] == '0' {
		return 0, fail(ErrInvalidSeq, pos)
	}
	n, ok := parseU32(numStr)
	if !ok {
		return 0, fail(ErrInvalidSeq, pos)
	}
	return n, nil
}

func parseU32(s string) (uint32, bool) {
	if len(s) == 0 {
		return 0, false
	}
	var result uint64
	for i := 0; i < len(s); i++ {
		d := s[i] - '0'
		if d > 9 {
			return 0, false
		}
		result = result*10 + uint64(d)
		if result > 0xFFFFFFFF {
			return 0, false
		}
	}
	return uint32(result), true
}

func validateAuth(s string, pos int) error {
	if len(s) != AuthTokenLen {
		return fail(ErrInvalidAuth, pos)
	}
	if s[0] != 'a' || s[1] != 't' {
		return fail(ErrInvalidAuth, pos)
	}
	for i := 2; i < len(s); i++ {
		ch := s[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return fail(ErrInvalidAuth, pos)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Scanning helpers
// ---------------------------------------------------------------------------

func findUnescapedChar(s string, target byte, start int) int {
	i := start
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == target {
			return i
		}
		i++
	}
	return -1
}

func findClosingBracket(s string, start int) int {
	i := start
	depth := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '[' {
			depth++
		} else if s[i] == ']' {
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

func findClosingBrace(s string, start int) int {
	i := start
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '}' {
			return i
		}
		i++
	}
	return -1
}

func scanUntilAny(s string, pos int, stops string) int {
	i := pos
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if strings.IndexByte(stops, s[i]) >= 0 {
			return i
		}
		i++
	}
	return i
}

func validateDigits(s string, pos int) error {
	if len(s) == 0 {
		return fail(ErrInvalidModifier, pos)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return fail(ErrInvalidModifier, pos)
		}
	}
	return nil
}

func validateTimestamp(s string, pos int) error {
	if len(s) == 0 {
		return fail(ErrInvalidVariable, pos)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return fail(ErrInvalidVariable, pos)
		}
	}
	return nil
}

func isHexDigit(ch byte) bool {
	return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// ---------------------------------------------------------------------------
// Metadata parsing
// ---------------------------------------------------------------------------

func parseMetaPair(s string, pos int) (MetaPair, error) {
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if s[i] == '=' {
			key := s[:i]
			value := s[i+1:]
			if err := validateMetaKey(key, pos); err != nil {
				return MetaPair{}, err
			}
			return MetaPair{Key: key, Value: value}, nil
		}
		i++
	}
	return MetaPair{}, fail(ErrInvalidMetadata, pos)
}

func parseMetadata(s string, basePos int) ([]MetaPair, error) {
	if len(s) == 0 {
		return nil, fail(ErrInvalidMetadata, basePos)
	}

	var pairs []MetaPair
	start := 0
	i := 0

	for {
		atEnd := i >= len(s)
		isComma := !atEnd && s[i] == ','

		if atEnd || isComma {
			pairStr := s[start:i]
			if len(pairStr) > 0 {
				if len(pairs) >= MaxMetaPairs {
					return nil, fail(ErrTooManyItems, basePos+start)
				}
				pair, err := parseMetaPair(pairStr, basePos+start)
				if err != nil {
					return nil, err
				}
				pairs = append(pairs, pair)
			}
			if atEnd {
				break
			}
			start = i + 1
			i++
			continue
		}

		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		i++
	}

	if len(pairs) == 0 {
		return nil, fail(ErrInvalidMetadata, basePos)
	}
	return pairs, nil
}

// ---------------------------------------------------------------------------
// Variable parsing
// ---------------------------------------------------------------------------

func findOperator(s string, basePos int) (int, int, Operator, error) {
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if i+1 < len(s) && s[i+1] == '=' {
			switch s[i] {
			case ':':
				return i, 2, OperatorNumber, nil
			case '?':
				return i, 2, OperatorBoolean, nil
			case '@':
				return i, 2, OperatorLocation, nil
			}
		}
		if s[i] == '=' {
			return i, 1, OperatorString, nil
		}
		i++
	}
	return 0, 0, 0, fail(ErrInvalidVariable, basePos)
}

func scanValue(s string, pos int) (int, int) {
	i := pos
	for i < len(s) {
		ch := s[i]
		if ch == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if ch == '#' || ch == '@' || ch == '^' || ch == '{' {
			return i, i
		}
		i++
	}
	return i, i
}

func parseValue(s string, op Operator, pos int) (Value, error) {
	switch op {
	case OperatorNumber:
		if len(s) == 0 {
			return Value{}, fail(ErrInvalidVariable, pos)
		}
		if err := validateNumber(s, pos); err != nil {
			return Value{}, err
		}
		return Value{Type: OperatorNumber, Str: s}, nil
	case OperatorString:
		if len(s) == 0 {
			return Value{}, fail(ErrInvalidVariable, pos)
		}
		return Value{Type: OperatorString, Str: s}, nil
	case OperatorBoolean:
		switch s {
		case "true":
			return Value{Type: OperatorBoolean, Bool: true}, nil
		case "false":
			return Value{Type: OperatorBoolean, Bool: false}, nil
		default:
			return Value{}, fail(ErrInvalidVariable, pos)
		}
	case OperatorLocation:
		return parseLocation(s, pos)
	}
	return Value{}, fail(ErrInvalidVariable, pos)
}

func parseLocation(s string, pos int) (Value, error) {
	commaCount := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			commaCount++
		}
	}
	if commaCount > 2 {
		return Value{}, fail(ErrInvalidVariable, pos)
	}

	parts := strings.SplitN(s, ",", 4)
	if len(parts) < 2 {
		return Value{}, fail(ErrInvalidVariable, pos)
	}
	lat := parts[0]
	lng := parts[1]
	if len(lat) == 0 || len(lng) == 0 {
		return Value{}, fail(ErrInvalidVariable, pos)
	}

	if err := validateNumber(lat, pos); err != nil {
		return Value{}, err
	}
	if err := validateNumber(lng, pos); err != nil {
		return Value{}, err
	}

	loc := &LocationValue{Lat: lat, Lng: lng}
	if len(parts) > 2 {
		alt := parts[2]
		if len(alt) == 0 {
			return Value{}, fail(ErrInvalidVariable, pos)
		}
		if err := validateNumber(alt, pos); err != nil {
			return Value{}, err
		}
		loc.Alt = &alt
	}

	return Value{Type: OperatorLocation, Location: loc}, nil
}

func parseVariable(s string, basePos int) (Variable, error) {
	opPos, opLen, operator, err := findOperator(s, basePos)
	if err != nil {
		return Variable{}, err
	}
	name := s[:opPos]
	if len(name) == 0 {
		return Variable{}, fail(ErrInvalidVariable, basePos)
	}
	if err := validateVarname(name, basePos); err != nil {
		return Variable{}, err
	}

	pos := opPos + opLen

	// Scan value
	valueStart := pos
	valueEnd, newPos := scanValue(s, pos)
	pos = newPos
	valueStr := s[valueStart:valueEnd]
	value, err := parseValue(valueStr, operator, basePos+valueStart)
	if err != nil {
		return Variable{}, err
	}

	var unit *string
	var timestamp *string
	var group *string
	var meta []MetaPair

	// #unit — NOT allowed with @= (location)
	if pos < len(s) && s[pos] == '#' {
		if operator == OperatorLocation {
			return Variable{}, fail(ErrInvalidVariable, basePos+pos)
		}
		pos++
		start := pos
		pos = scanUntilAny(s, pos, "@^{")
		u := s[start:pos]
		if err := validateUnit(u, basePos+start); err != nil {
			return Variable{}, err
		}
		unit = &u
	}

	// @timestamp
	if pos < len(s) && s[pos] == '@' {
		pos++
		start := pos
		pos = scanUntilAny(s, pos, "^{")
		ts := s[start:pos]
		if err := validateTimestamp(ts, basePos+start); err != nil {
			return Variable{}, err
		}
		timestamp = &ts
	}

	// ^group
	if pos < len(s) && s[pos] == '^' {
		pos++
		start := pos
		pos = scanUntilAny(s, pos, "{")
		g := s[start:pos]
		if err := validateGroup(g, basePos+start); err != nil {
			return Variable{}, err
		}
		group = &g
	}

	// {metadata}
	if pos < len(s) && s[pos] == '{' {
		pos++
		start := pos
		end := findClosingBrace(s, pos)
		if end == -1 {
			return Variable{}, fail(ErrInvalidMetadata, basePos+start)
		}
		metaStr := s[start:end]
		m, err := parseMetadata(metaStr, basePos+start)
		if err != nil {
			return Variable{}, err
		}
		meta = m
		pos = end + 1
	}

	_ = pos

	return Variable{
		Name:      name,
		Operator:  operator,
		Value:     value,
		Unit:      unit,
		Timestamp: timestamp,
		Group:     group,
		Meta:      meta,
	}, nil
}

// ---------------------------------------------------------------------------
// Variable list parsing
// ---------------------------------------------------------------------------

func parseVariableList(s string, basePos int) ([]Variable, error) {
	var variables []Variable
	start := 0
	i := 0

	for {
		atEnd := i >= len(s)
		isSemi := !atEnd && s[i] == ';'

		if atEnd || isSemi {
			varStr := s[start:i]
			if len(varStr) > 0 {
				if len(variables) >= MaxVariables {
					return nil, fail(ErrTooManyItems, basePos+start)
				}
				v, err := parseVariable(varStr, basePos+start)
				if err != nil {
					return nil, err
				}
				variables = append(variables, v)
			}
			if atEnd {
				break
			}
			start = i + 1
			i++
			continue
		}

		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		i++
	}

	return variables, nil
}

// ---------------------------------------------------------------------------
// Body-level modifiers
// ---------------------------------------------------------------------------

type bodyModifiers struct {
	group     *string
	timestamp *string
	meta      []MetaPair
}

func parseBodyModifiers(s string, basePos int) (bodyModifiers, error) {
	if len(s) == 0 {
		return bodyModifiers{}, nil
	}

	pos := 0
	var group *string
	var timestamp *string
	var meta []MetaPair
	phase := 0 // 0=^, 1=@, 2={, 3=done

	for pos < len(s) {
		ch := s[pos]
		switch ch {
		case '^':
			if phase > 0 {
				return bodyModifiers{}, fail(ErrInvalidModifier, basePos+pos)
			}
			pos++
			start := pos
			pos = scanUntilAny(s, pos, "@{")
			g := s[start:pos]
			if err := validateGroup(g, basePos+start); err != nil {
				return bodyModifiers{}, err
			}
			group = &g
			phase = 1
		case '@':
			if phase > 1 {
				return bodyModifiers{}, fail(ErrInvalidModifier, basePos+pos)
			}
			pos++
			start := pos
			pos = scanUntilAny(s, pos, "{")
			ts := s[start:pos]
			if err := validateDigits(ts, basePos+start); err != nil {
				return bodyModifiers{}, err
			}
			timestamp = &ts
			phase = 2
		case '{':
			if phase > 2 {
				return bodyModifiers{}, fail(ErrInvalidModifier, basePos+pos)
			}
			pos++
			start := pos
			end := findUnescapedChar(s, '}', pos)
			if end == -1 {
				return bodyModifiers{}, fail(ErrInvalidMetadata, basePos+start)
			}
			metaStr := s[start:end]
			m, err := parseMetadata(metaStr, basePos+start)
			if err != nil {
				return bodyModifiers{}, err
			}
			meta = m
			pos = end + 1
			phase = 3
		default:
			return bodyModifiers{}, fail(ErrInvalidModifier, basePos+pos)
		}
	}

	return bodyModifiers{group: group, timestamp: timestamp, meta: meta}, nil
}

// ---------------------------------------------------------------------------
// PUSH body parsing
// ---------------------------------------------------------------------------

func parsePushBody(body string, basePos int) (*PushBody, error) {
	if strings.HasPrefix(body, ">x") {
		return parseHexPassthrough(body[2:], basePos+2)
	}
	if strings.HasPrefix(body, ">b") {
		return parseBase64Passthrough(body[2:], basePos+2)
	}

	bracketPos := findUnescapedChar(body, '[', 0)
	if bracketPos == -1 {
		return nil, fail(ErrInvalidVarBlock, basePos)
	}

	modStr := body[:bracketPos]
	endBracket := findClosingBracket(body, bracketPos+1)
	if endBracket == -1 {
		return nil, fail(ErrInvalidVarBlock, basePos+bracketPos)
	}

	varBlock := body[bracketPos+1 : endBracket]
	if len(varBlock) == 0 {
		return nil, fail(ErrInvalidVarBlock, basePos+bracketPos)
	}

	mods, err := parseBodyModifiers(modStr, basePos)
	if err != nil {
		return nil, err
	}
	variables, err := parseVariableList(varBlock, basePos+bracketPos+1)
	if err != nil {
		return nil, err
	}
	if len(variables) == 0 {
		return nil, fail(ErrInvalidVarBlock, basePos+bracketPos)
	}

	sb := &StructuredBody{
		Variables: variables,
		Group:     mods.group,
		Timestamp: mods.timestamp,
		Meta:      mods.meta,
	}

	return &PushBody{Structured: sb}, nil
}

func parseHexPassthrough(data string, pos int) (*PushBody, error) {
	if len(data) == 0 {
		return nil, fail(ErrInvalidPassthru, pos)
	}
	if len(data)%2 != 0 {
		return nil, fail(ErrInvalidPassthru, pos)
	}
	for i := 0; i < len(data); i++ {
		if !isHexDigit(data[i]) {
			return nil, fail(ErrInvalidPassthru, pos)
		}
	}
	return &PushBody{
		IsPassthrough: true,
		Passthrough: &PassthroughBody{
			Encoding: PassthroughEncodingHex,
			Data:     data,
		},
	}, nil
}

func parseBase64Passthrough(data string, pos int) (*PushBody, error) {
	if len(data) == 0 {
		return nil, fail(ErrInvalidPassthru, pos)
	}
	for i := 0; i < len(data); i++ {
		ch := data[i]
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=') {
			return nil, fail(ErrInvalidPassthru, pos)
		}
	}
	return &PushBody{
		IsPassthrough: true,
		Passthrough: &PassthroughBody{
			Encoding: PassthroughEncodingBase64,
			Data:     data,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// PULL body parsing
// ---------------------------------------------------------------------------

func parsePullBody(body string, basePos int) (*PullBody, error) {
	if len(body) < 2 || body[0] != '[' || body[len(body)-1] != ']' {
		return nil, fail(ErrMissingBody, basePos)
	}

	inner := body[1 : len(body)-1]
	if len(inner) == 0 {
		return nil, fail(ErrInvalidVarBlock, basePos)
	}

	var variables []string
	start := 0
	i := 0

	for {
		atEnd := i >= len(inner)
		isSemi := !atEnd && inner[i] == ';'

		if atEnd || isSemi {
			name := inner[start:i]
			if len(name) > 0 {
				if len(variables) >= MaxVariables {
					return nil, fail(ErrTooManyItems, basePos+1+start)
				}
				if err := validateVarname(name, basePos+1+start); err != nil {
					return nil, err
				}
				variables = append(variables, name)
			}
			if atEnd {
				break
			}
			start = i + 1
			i++
			continue
		}

		if inner[i] == '\\' && i+1 < len(inner) {
			i += 2
			continue
		}
		i++
	}

	if len(variables) == 0 {
		return nil, fail(ErrInvalidVarBlock, basePos)
	}
	return &PullBody{Variables: variables}, nil
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// ParseUplink parses a raw uplink frame string into an UplinkFrame.
func ParseUplink(input string) (*UplinkFrame, error) {
	if strings.ContainsRune(input, '\x00') {
		return nil, fail(ErrNulByte, 0)
	}
	if len(input) > MaxFrameSize {
		return nil, fail(ErrFrameTooLarge, 0)
	}

	stripped := input
	if len(stripped) > 0 && stripped[len(stripped)-1] == '\n' {
		stripped = stripped[:len(stripped)-1]
	}
	fields := splitFields(stripped)

	if len(fields) == 0 || len(fields[0]) == 0 {
		return nil, fail(ErrEmptyFrame, 0)
	}

	method, err := parseMethod(fields[0])
	if err != nil {
		return nil, err
	}

	var seq *uint32
	authIdx := 1
	if len(fields) > 1 && len(fields[1]) > 0 && fields[1][0] == '!' {
		s, err := parseSeq(fields[1], len(fields[0])+1)
		if err != nil {
			return nil, err
		}
		seq = &s
		authIdx = 2
	}

	authPos := 0
	for i := 0; i < authIdx; i++ {
		authPos += len(fields[i]) + 1
	}

	if len(fields) <= authIdx {
		return nil, fail(ErrInvalidAuth, authPos)
	}
	auth := fields[authIdx]
	if err := validateAuth(auth, authPos); err != nil {
		return nil, err
	}

	serialIdx := authIdx + 1
	serialPos := authPos + len(auth) + 1
	if len(fields) <= serialIdx {
		return nil, fail(ErrInvalidSerial, serialPos)
	}
	serial := fields[serialIdx]
	if err := validateSerial(serial, serialPos); err != nil {
		return nil, err
	}

	bodyIdx := serialIdx + 1
	bodyPos := serialPos + len(serial) + 1

	frame := &UplinkFrame{
		Method: method,
		Seq:    seq,
		Auth:   auth,
		Serial: serial,
	}

	switch method {
	case MethodPush:
		if len(fields) <= bodyIdx {
			return nil, fail(ErrMissingBody, bodyPos)
		}
		pb, err := parsePushBody(fields[bodyIdx], bodyPos)
		if err != nil {
			return nil, err
		}
		frame.PushBody = pb
	case MethodPull:
		if len(fields) <= bodyIdx {
			return nil, fail(ErrMissingBody, bodyPos)
		}
		pb, err := parsePullBody(fields[bodyIdx], bodyPos)
		if err != nil {
			return nil, err
		}
		frame.PullBody = pb
	case MethodPing:
		// No body for PING
	}

	return frame, nil
}

// ParseAck parses a raw ACK frame string into an AckFrame.
func ParseAck(input string) (*AckFrame, error) {
	stripped := input
	if len(stripped) > 0 && stripped[len(stripped)-1] == '\n' {
		stripped = stripped[:len(stripped)-1]
	}
	fields := splitFields(stripped)

	if len(fields) == 0 || fields[0] != "ACK" {
		return nil, fail(ErrInvalidAck, 0)
	}
	if len(fields) < 2 {
		return nil, fail(ErrInvalidAck, 0)
	}

	var seq *uint32
	statusIdx := 1
	if len(fields[1]) > 0 && fields[1][0] == '!' {
		s, err := parseSeq(fields[1], 4)
		if err != nil {
			return nil, err
		}
		seq = &s
		statusIdx = 2
	}

	if len(fields) <= statusIdx {
		return nil, fail(ErrInvalidAck, 0)
	}

	status, err := parseAckStatus(fields[statusIdx])
	if err != nil {
		return nil, err
	}

	var detail *AckDetail
	if len(fields) > statusIdx+1 {
		detail = parseAckDetail(fields[statusIdx+1], status)
	}

	return &AckFrame{
		Seq:    seq,
		Status: status,
		Detail: detail,
	}, nil
}

func parseAckStatus(s string) (AckStatus, error) {
	switch s {
	case "OK":
		return AckStatusOk, nil
	case "PONG":
		return AckStatusPong, nil
	case "CMD":
		return AckStatusCmd, nil
	case "ERR":
		return AckStatusErr, nil
	default:
		return 0, fail(ErrInvalidAck, 0)
	}
}

func parseAckDetail(s string, status AckStatus) *AckDetail {
	switch status {
	case AckStatusOk:
		if len(s) > 0 && s[0] == '[' {
			return &AckDetail{Type: "variables", Text: s}
		}
		if n, ok := parseU32(s); ok {
			return &AckDetail{Type: "count", Count: n}
		}
		return &AckDetail{Type: "raw", Text: s}
	case AckStatusPong:
		return &AckDetail{Type: "raw", Text: s}
	case AckStatusCmd:
		return &AckDetail{Type: "command", Text: s}
	case AckStatusErr:
		code := parseErrorCodeStr(s)
		return &AckDetail{Type: "error", ErrorCode: code, Text: s}
	}
	return &AckDetail{Type: "raw", Text: s}
}

func parseErrorCodeStr(s string) ErrorCode {
	switch s {
	case "invalid_token":
		return ErrorCodeInvalidToken
	case "invalid_method":
		return ErrorCodeInvalidMethod
	case "invalid_payload":
		return ErrorCodeInvalidPayload
	case "invalid_seq":
		return ErrorCodeInvalidSeq
	case "device_not_found":
		return ErrorCodeDeviceNotFound
	case "variable_not_found":
		return ErrorCodeVariableNotFound
	case "rate_limited":
		return ErrorCodeRateLimited
	case "auth_failed":
		return ErrorCodeAuthFailed
	case "unsupported_version":
		return ErrorCodeUnsupportedVersion
	case "payload_too_large":
		return ErrorCodePayloadTooLarge
	case "server_error":
		return ErrorCodeServerError
	default:
		return ErrorCodeUnknown
	}
}
