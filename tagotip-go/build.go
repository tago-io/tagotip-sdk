package tagotip

import (
	"fmt"
	"strings"
)

func writeValue(op Operator, v Value) string {
	switch op {
	case OperatorNumber:
		if v.Type != OperatorNumber {
			return ":="
		}
		return ":=" + v.Str
	case OperatorString:
		if v.Type != OperatorString {
			return "="
		}
		return "=" + v.Str
	case OperatorBoolean:
		if v.Type != OperatorBoolean {
			return "?="
		}
		if v.Bool {
			return "?=true"
		}
		return "?=false"
	case OperatorLocation:
		if v.Type != OperatorLocation || v.Location == nil {
			return "@="
		}
		loc := v.Location
		s := "@=" + loc.Lat + "," + loc.Lng
		if loc.Alt != nil {
			s += "," + *loc.Alt
		}
		return s
	}
	return "="
}

func writeMetaPairs(pairs []MetaPair) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p.Key)
		b.WriteByte('=')
		b.WriteString(p.Value)
	}
	b.WriteByte('}')
	return b.String()
}

func writeVariable(v Variable) string {
	var b strings.Builder
	b.WriteString(v.Name)
	b.WriteString(writeValue(v.Operator, v.Value))
	if v.Unit != nil {
		b.WriteByte('#')
		b.WriteString(*v.Unit)
	}
	if v.Timestamp != nil {
		b.WriteByte('@')
		b.WriteString(*v.Timestamp)
	}
	if v.Group != nil {
		b.WriteByte('^')
		b.WriteString(*v.Group)
	}
	if len(v.Meta) > 0 {
		b.WriteString(writeMetaPairs(v.Meta))
	}
	return b.String()
}

func writePushBody(body *PushBody) string {
	if body.IsPassthrough && body.Passthrough != nil {
		pt := body.Passthrough
		prefix := ">x"
		if pt.Encoding == PassthroughEncodingBase64 {
			prefix = ">b"
		}
		return prefix + pt.Data
	}

	sb := body.Structured
	if sb == nil {
		return "[]"
	}

	var b strings.Builder
	if sb.Group != nil {
		b.WriteByte('^')
		b.WriteString(*sb.Group)
	}
	if sb.Timestamp != nil {
		b.WriteByte('@')
		b.WriteString(*sb.Timestamp)
	}
	if len(sb.Meta) > 0 {
		b.WriteString(writeMetaPairs(sb.Meta))
	}
	b.WriteByte('[')
	for i, v := range sb.Variables {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(writeVariable(v))
	}
	b.WriteByte(']')
	return b.String()
}

func writePullBody(body *PullBody) string {
	return "[" + strings.Join(body.Variables, ";") + "]"
}

// BuildUplink serializes an UplinkFrame into a raw frame string.
func BuildUplink(frame *UplinkFrame) (string, error) {
	if frame == nil {
		return "", fmt.Errorf("tagotip: nil frame")
	}

	var parts []string

	switch frame.Method {
	case MethodPush:
		parts = append(parts, "PUSH")
	case MethodPull:
		parts = append(parts, "PULL")
	case MethodPing:
		parts = append(parts, "PING")
	}

	if frame.Seq != nil {
		parts = append(parts, fmt.Sprintf("!%d", *frame.Seq))
	}

	parts = append(parts, frame.Auth)
	parts = append(parts, frame.Serial)

	result := strings.Join(parts, "|")

	if frame.Method == MethodPush && frame.PushBody != nil {
		result += "|" + writePushBody(frame.PushBody)
	} else if frame.Method == MethodPull && frame.PullBody != nil {
		result += "|" + writePullBody(frame.PullBody)
	}

	return result, nil
}

// BuildAck serializes an AckFrame into a raw frame string.
func BuildAck(frame *AckFrame) (string, error) {
	if frame == nil {
		return "", fmt.Errorf("tagotip: nil frame")
	}

	parts := []string{"ACK"}

	if frame.Seq != nil {
		parts = append(parts, fmt.Sprintf("!%d", *frame.Seq))
	}

	switch frame.Status {
	case AckStatusOk:
		parts = append(parts, "OK")
	case AckStatusPong:
		parts = append(parts, "PONG")
	case AckStatusCmd:
		parts = append(parts, "CMD")
	case AckStatusErr:
		parts = append(parts, "ERR")
	}

	if frame.Detail != nil {
		switch frame.Detail.Type {
		case "count":
			parts = append(parts, fmt.Sprintf("%d", frame.Detail.Count))
		case "variables":
			parts = append(parts, frame.Detail.Text)
		case "command":
			parts = append(parts, frame.Detail.Text)
		case "error":
			parts = append(parts, frame.Detail.Text)
		case "raw":
			parts = append(parts, frame.Detail.Text)
		}
	}

	return strings.Join(parts, "|"), nil
}
