package httpio

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type HTTPError struct {
	Status  int
	Message string
}

func (he *HTTPError) Error() string {
	return he.Message
}

func UnmarshalJSON(r *http.Request, input interface{}) *HTTPError {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
	}
	err = json.Unmarshal(data, input)
	if err != nil {
		log.Println(err)
	}
	return &HTTPError{
		Status:  http.StatusBadRequest,
		Message: fmt.Sprintf("Unable to parse JSON input - '%s'", err.Error()),
	}
}

func SendJSON(w http.ResponseWriter, resp interface{}, err error) {
	status := http.StatusInsufficientStorage
	msg := ""
	if herr, ok := err.(*HTTPError); ok {
		status = herr.Status
		msg = herr.Message
	}
	w.WriteHeader(status)
	w.Write([]byte(msg))
}
