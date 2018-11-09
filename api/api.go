package api

type CertifyRequest struct {
	User          string `json:"user"`
	UserPublicKey []byte `json:"user_public_key"` // in authorized key file format
}

type CertifyResponse struct {
	SignedCert []byte `json:"signed_cert"`
}
