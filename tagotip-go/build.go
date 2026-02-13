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

// BuildHeadless serializes a HeadlessFrame for TagoTiP/S.
// The method determines the output format:
//   - PUSH: SERIAL|BODY
//   - PULL: SERIAL|[VARNAME;...]
//   - PING: SERIAL
func BuildHeadless(method Method, frame *HeadlessFrame) (string, error) {
	if frame == nil {
		return "", fmt.Errorf("tagotip: nil frame")
	}

	switch method {
	case MethodPush:
		if frame.PushBody == nil {
			return "", fmt.Errorf("tagotip: PUSH headless frame requires push body")
		}
		return frame.Serial + "|" + writePushBody(frame.PushBody), nil
	case MethodPull:
		if frame.PullBody == nil {
			return "", fmt.Errorf("tagotip: PULL headless frame requires pull body")
		}
		return frame.Serial + "|" + writePullBody(frame.PullBody), nil
	case MethodPing:
		return frame.Serial, nil
	}

	return "", fmt.Errorf("tagotip: unknown method")
}

// BuildAckInner serializes an AckFrame into a TagoTiP/S inner frame (STATUS[|DETAIL], no ACK| prefix).
func BuildAckInner(frame *AckFrame) (string, error) {
	if frame == nil {
		return "", fmt.Errorf("tagotip: nil frame")
	}

	var status string
	switch frame.Status {
	case AckStatusOk:
		status = "OK"
	case AckStatusPong:
		status = "PONG"
	case AckStatusCmd:
		status = "CMD"
	case AckStatusErr:
		status = "ERR"
	}

	if frame.Detail == nil {
		return status, nil
	}

	var detailStr string
	switch frame.Detail.Type {
	case "count":
		detailStr = fmt.Sprintf("%d", frame.Detail.Count)
	case "variables":
		detailStr = frame.Detail.Text
	case "command":
		detailStr = frame.Detail.Text
	case "error":
		detailStr = frame.Detail.Text
	case "raw":
		detailStr = frame.Detail.Text
	}

	return status + "|" + detailStr, nil
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
