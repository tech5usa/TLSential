package acme

// Trigger an ACME request for the id
type Service interface {
	Trigger(id string)
}
