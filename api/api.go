package api

type CertifyRequest struct {
	User          string `json:"user"`
	UserPublicKey []byte `json:"user_public_key"` // in authorized key file format
	Host          string `json:"host"`
}
