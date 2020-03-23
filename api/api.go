package api

import "errors"

var (
	// ErrMissingID is returned when you made a call that isn't supported
	// without an ID in the URI
	ErrMissingID = errors.New("Missing identifier in URI") // 400
	// ErrMismatchedID is returned when the post body doesn't match the URI
	ErrMismatchedID = errors.New("URI doesn't match provided data") // 400
	// ErrBodyRequired is returned if a request did not contain a body when one
	// was needed.
	ErrBodyRequired = errors.New("Body is required for this endpoint") // 400
)
