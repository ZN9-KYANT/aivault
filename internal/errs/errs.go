// Package errs holds shared sentinel errors used across aivault packages.
package errs

import "errors"

// ErrNotImplemented is returned by scaffold stubs whose implementation is
// scheduled for a later milestone.
var ErrNotImplemented = errors.New("not implemented (scheduled milestone)")
