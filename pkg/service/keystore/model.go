package keystore

type StoreKeyRequest struct {
	ID         string
	Type       string
	Controller string
	Key        []byte
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
