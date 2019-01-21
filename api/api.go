package api

type ClientInfo struct {
	Agent    string `json:"agent"`
	Hostname string `json:"hostname"`
}

type CertifyRequest struct {
	User          string     `json:"user"`
	UserPublicKey []byte     `json:"user_public_key"` // in authorized key file format
	ClientInfo    ClientInfo `json:"client_info"`
}

type CertifyResponse struct {
	SignedCert []byte `json:"signed_cert"`
	Comment    string `json:"comment"`
}

type OAuthInitRequest struct {
	ClientInfo ClientInfo `json:"client_info"`
}

type OAuthInitResponse struct {
	OAuthURL  string `json:"oauth_url"`
	SessionID string `json:"session_id"`
}
