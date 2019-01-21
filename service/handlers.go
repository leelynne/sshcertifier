package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/leelynne/sshcertifier/api"
	"golang.org/x/oauth2"
)

const loggerCtxKey = "logger"

func (sc *SSHCertifier) getMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/certify/user", sc.loggerMiddleware(
		http.HandlerFunc(sc.handleCertifyUser)))
	mux.Handle("/oauth/init", sc.loggerMiddleware(
		http.HandlerFunc(sc.handleOauthInit)))
	mux.Handle("/hub/oauth_callback", sc.loggerMiddleware(
		http.HandlerFunc(sc.handleOauthCallback)))
	return mux
}

func (sc *SSHCertifier) loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loggerCtxKey, sc.logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (sc *SSHCertifier) handleCertifyUser(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	splitToken := strings.Split(authHeader, "Bearer")
	if len(splitToken) != 2 {
		http.Error(w, "Invalid token", 400)
		return
	}

	_ = &oauth2.Token{
		AccessToken: splitToken[1],
	}

	reqBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Could not read request", 400)
		return
	}
	_ = r.Header.Get("Authorization")
	// Validate token
	certReq := api.CertifyRequest{}
	err = json.Unmarshal(reqBytes, &certReq)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	sc.logger.Info("oauth done")
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
	buf.WriteString(cert.Type())
	buf.WriteByte(' ')
	buf.WriteString(base64.StdEncoding.EncodeToString(cert.Marshal()))
	buf.WriteByte(' ')
	buf.WriteString(certReq.User)
	buf.WriteByte('\n')

	sc.logger.Info("Issuing cert2", "user", certReq.User, "serial", cert.Serial)

	acceptType := r.Header.Get("Accept")
	var respBytes []byte
	if acceptType == "application/json" {
		resp := api.CertifyResponse{
			SignedCert: buf.Bytes(),
			Comment:    certReq.User,
		}
		respBytes, err = json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else {
		respBytes = buf.Bytes()
	}

	w.Write(respBytes)
}

func (sc *SSHCertifier) handleOauthInit(w http.ResponseWriter, r *http.Request) {
	resp := api.OAuthInitResponse{}

	resp.OAuthURL = sc.oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOnline)
	resp.SessionID = "testsid123"
	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(respBytes)

}

func (sc *SSHCertifier) handleOauthCallback(w http.ResponseWriter, r *http.Request) {
	_ = r.FormValue("state") // validate
	code := r.FormValue("code")
	t, err := sc.oauthConfig.Exchange(context.Background(), code)
	if err == nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	resp := api.OAuthInitResponse{}
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	resp.OAuthURL = sc.oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOnline)
	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(respBytes)

}
