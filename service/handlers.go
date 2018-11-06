package service

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/leelynne/sshcertifier/api"
)

func (sc *SSHCertifier) HandleCertify(w http.ResponseWriter, r *http.Request) {
	reqBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Could not read request", 400)
		return
	}
	certReq := api.CertifyRequest{}
	err = json.Unmarshal(reqBytes, &certReq)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	cert, err := sc.createCert(certReq.User, certReq.UserPublicKey, certReq.Host, []string{"admin", "ops"}, time.Hour*24)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(cert)
}
