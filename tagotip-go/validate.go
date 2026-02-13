package tagotip

func isLowercaseAlnumUnderscore(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}

func isSerialChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func validateVarname(s string, pos int) error {
	if len(s) == 0 || len(s) > MaxVarNameLen {
		return fail(ErrInvalidVariable, pos)
	}
	for i := 0; i < len(s); i++ {
		if !isLowercaseAlnumUnderscore(s[i]) {
			return fail(ErrInvalidVariable, pos)
		}
	}
	return nil
}

func validateSerial(s string, pos int) error {
	if len(s) == 0 || len(s) > MaxSerialLen {
		return fail(ErrInvalidSerial, pos)
	}
	for i := 0; i < len(s); i++ {
		if !isSerialChar(s[i]) {
			return fail(ErrInvalidSerial, pos)
		}
	}
	return nil
}

func validateGroup(s string, pos int) error {
	if len(s) == 0 || len(s) > MaxGroupLen {
		return fail(ErrInvalidVariable, pos)
	}
	for i := 0; i < len(s); i++ {
		if !isLowercaseAlnumUnderscore(s[i]) {
			return fail(ErrInvalidVariable, pos)
		}
	}
	return nil
}

func validateMetaKey(s string, pos int) error {
	if len(s) == 0 || len(s) > MaxMetaKeyLen {
		return fail(ErrInvalidMetadata, pos)
	}
	for i := 0; i < len(s); i++ {
		if !isLowercaseAlnumUnderscore(s[i]) {
			return fail(ErrInvalidMetadata, pos)
		}
	}
	return nil
}

func validateUnit(s string, pos int) error {
	if len(s) == 0 || len(s) > MaxUnitLen {
		return fail(ErrInvalidVariable, pos)
	}
	return nil
}

func validateNumber(s string, pos int) error {
	if len(s) == 0 {
		return fail(ErrInvalidVariable, pos)
	}
	i := 0
	if s[i] == '-' {
		i++
		if i >= len(s) {
			return fail(ErrInvalidVariable, pos)
		}
	}
	if i >= len(s) || s[i] < '0' || s[i] > '9' {
		return fail(ErrInvalidVariable, pos)
	}
	if s[i] == '0' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
		return fail(ErrInvalidVariable, pos)
	}
	i++
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i < len(s) && s[i] == '.' {
		i++
		if i >= len(s) || s[i] < '0' || s[i] > '9' {
			return fail(ErrInvalidVariable, pos)
		}
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	if i != len(s) {
		return fail(ErrInvalidVariable, pos)
	}
	return nil
}
