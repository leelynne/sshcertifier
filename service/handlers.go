package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/inconshreveable/log15"
	"github.com/leelynne/sshcertifier/api"
)

const loggerCtxKey = "logger"

func (sc *SSHCertifier) getMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/certify/user", sc.loggerMiddleware(
		http.HandlerFunc(sc.handleCertifyUser)))
	return mux
}

func (sc *SSHCertifier) loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loggerCtxKey, sc.logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (sc *SSHCertifier) handleCertifyUser(w http.ResponseWriter, r *http.Request) {
	logger := getLogger(r.Context())
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
	cert, err := sc.createCert(certReq.User, certReq.UserPublicKey, []string{"admin", "ops"}, time.Hour*24)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	buf := bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("%s ", cert.Type()))
	buf.WriteString(base64.StdEncoding.EncodeToString(cert.Marshal()))
	if certReq.Host != "" {
		buf.WriteString(fmt.Sprintf(" %s\n", certReq.Host))
	} else {
		buf.WriteString("\n")
	}

	logger.Info("Issuing cert", "user", certReq.User, "serial", cert.Serial)
	resp := api.CertifyResponse{
		SignedCert: buf.Bytes(),
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(respBytes)
}

func getLogger(ctx context.Context) log.Logger {
	return nil
}
