package keystore

type StoreKeyRequest struct {
	ID         string
	Type       string
	Controller string
	Key        interface{}
}

type GetKeyDetailsRequest struct {
	ID string
}

type GetKeyDetailsResponse struct {
	ID         string
	Type       string
	Controller string
	CreatedAt  string
}
