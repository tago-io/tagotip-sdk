package tagotip

import "fmt"

// ParseErrorKind identifies the category of parse error.
type ParseErrorKind string

const (
	ErrEmptyFrame        ParseErrorKind = "empty_frame"
	ErrNulByte           ParseErrorKind = "nul_byte"
	ErrInvalidMethod     ParseErrorKind = "invalid_method"
	ErrInvalidSeq        ParseErrorKind = "invalid_seq"
	ErrInvalidAuth       ParseErrorKind = "invalid_auth"
	ErrInvalidSerial     ParseErrorKind = "invalid_serial"
	ErrMissingBody       ParseErrorKind = "missing_body"
	ErrInvalidModifier   ParseErrorKind = "invalid_modifier"
	ErrInvalidVarBlock   ParseErrorKind = "invalid_variable_block"
	ErrInvalidVariable   ParseErrorKind = "invalid_variable"
	ErrInvalidPassthru   ParseErrorKind = "invalid_passthrough"
	ErrInvalidMetadata   ParseErrorKind = "invalid_metadata"
	ErrInvalidField      ParseErrorKind = "invalid_field"
	ErrInvalidAck        ParseErrorKind = "invalid_ack"
	ErrTooManyItems      ParseErrorKind = "too_many_items"
	ErrFrameTooLarge     ParseErrorKind = "frame_too_large"
)

// ParseError is the error returned by the parsing functions.
type ParseError struct {
	Kind     ParseErrorKind
	Position int
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("tagotip: %s at position %d", e.Kind, e.Position)
}

func fail(kind ParseErrorKind, pos int) error {
	return &ParseError{Kind: kind, Position: pos}
}
