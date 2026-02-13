package tagotip

// Method represents the uplink frame method.
type Method int

const (
	MethodPush Method = iota
	MethodPull
	MethodPing
)

// Operator represents the variable value type hint.
type Operator int

const (
	OperatorNumber Operator = iota
	OperatorString
	OperatorBoolean
	OperatorLocation
)

// AckStatus represents the ACK response status.
type AckStatus int

const (
	AckStatusOk AckStatus = iota
	AckStatusPong
	AckStatusCmd
	AckStatusErr
)

// ErrorCode represents known error codes from the protocol spec.
type ErrorCode int

const (
	ErrorCodeInvalidToken ErrorCode = iota
	ErrorCodeInvalidMethod
	ErrorCodeInvalidPayload
	ErrorCodeInvalidSeq
	ErrorCodeDeviceNotFound
	ErrorCodeVariableNotFound
	ErrorCodeRateLimited
	ErrorCodeAuthFailed
	ErrorCodeUnsupportedVersion
	ErrorCodePayloadTooLarge
	ErrorCodeServerError
	ErrorCodeUnknown
)

// PassthroughEncoding represents binary passthrough encoding.
type PassthroughEncoding int

const (
	PassthroughEncodingHex PassthroughEncoding = iota
	PassthroughEncodingBase64
)

// MetaPair is a metadata key-value pair.
type MetaPair struct {
	Key   string
	Value string
}

// LocationValue holds lat/lng/alt for a location value.
type LocationValue struct {
	Lat string
	Lng string
	Alt *string // nil if not present
}

// Value represents a parsed variable value.
type Value struct {
	Type     Operator // Discriminant matching operator
	Str      string   // Number or String raw value
	Bool     bool     // Boolean value
	Location *LocationValue
}

// Variable represents a parsed variable with optional suffixes.
type Variable struct {
	Name      string
	Operator  Operator
	Value     Value
	Unit      *string // nil if not present
	Timestamp *string // nil if not present
	Group     *string // nil if not present
	Meta      []MetaPair
}

// StructuredBody represents a structured PUSH body.
type StructuredBody struct {
	Group     *string
	Timestamp *string
	Meta      []MetaPair
	Variables []Variable
}

// PassthroughBody represents a passthrough PUSH body.
type PassthroughBody struct {
	Encoding PassthroughEncoding
	Data     string
}

// PushBody represents a PUSH body (structured or passthrough).
type PushBody struct {
	IsPassthrough bool
	Structured    *StructuredBody
	Passthrough   *PassthroughBody
}

// PullBody represents a PULL body with variable names.
type PullBody struct {
	Variables []string
}

// UplinkFrame represents a fully parsed uplink frame.
type UplinkFrame struct {
	Method   Method
	Seq      *uint32 // nil if no sequence counter
	Auth     string
	Serial   string
	PushBody *PushBody
	PullBody *PullBody
}

// HeadlessFrame represents a headless inner frame for TagoTiP/S.
// It contains only serial and body — method, auth, and counter are
// carried by the envelope header.
type HeadlessFrame struct {
	Serial   string
	PushBody *PushBody
	PullBody *PullBody
}

// AckDetail represents the detail in an ACK frame.
type AckDetail struct {
	Type      string // "count", "variables", "command", "error", "raw"
	Count     uint32
	Text      string
	ErrorCode ErrorCode
}

// AckFrame represents a parsed ACK (downlink) frame.
type AckFrame struct {
	Seq    *uint32
	Status AckStatus
	Detail *AckDetail
}
