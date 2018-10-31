package service

import (
	"io/ioutil"
	"testing"
)

func TestCreate(t *testing.T) {
	raw, err := ioutil.ReadFile("/home/lee/.ssh/id_rsa.pub")
	if err != nil {
		t.Error(err)
	}
	err = crsToCrtExample("leef", raw, []string{"engineering"})
	if err != nil {
		t.Error(err)
	}

}
