package service

import (
	"errors"
	"fmt"
)

// ErrValidation marks an error as a caller-caused (client-fixable) input
// validation failure whose message is SAFE to return to the client. It is
// the discriminator handlers use to classify a service error:
//
//   - errors.Is(err, ErrValidation) → HTTP 400, echo err.Error() (the
//     validation feedback the caller needs to fix their request).
//   - anything else (DB / IO / internal, %w-wrapped) → HTTP 500 with a
//     generic client message; the raw error goes to the server log only.
//
// F443: before this, several Create/Update handlers echoed the raw service
// error at a blanket 400, conflating legitimate validation feedback with
// %w-wrapped DB errors — so an internal DB failure both returned the wrong
// status (400) and leaked the driver error string to the client.
//
// Wrapping is ADDITIVE: ValidationErrorf only makes errors.Is(err,
// ErrValidation) true and preserves the exact client-facing message, so
// existing callers that merely propagate the error (e.g. the triage/CRA
// VEX-sync path through CreateStatement) are unaffected.
var ErrValidation = errors.New("validation")

// ValidationErrorf builds a validation error: errors.Is(_, ErrValidation) is
// true and Error() returns exactly the formatted message (no sentinel
// suffix), so the handler can echo it verbatim at 400.
func ValidationErrorf(format string, args ...any) error {
	return &validationError{msg: fmt.Sprintf(format, args...)}
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

func (e *validationError) Is(target error) bool { return target == ErrValidation }
