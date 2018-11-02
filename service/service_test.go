package service

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestCreate(t *testing.T) {
	raw, err := ioutil.ReadFile("/home/lee/.ssh/id_ed25519.pub")
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("Len key: %d\n", len(raw))
	err = crsToCrtExample("leef", raw, []string{"engineering"})
	if err != nil {
		t.Error(err)
	}

}
