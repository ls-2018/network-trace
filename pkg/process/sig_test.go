package process

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSig(t *testing.T) {
	a, err := Parse(1)
	if err != nil {
		t.Fatal(err)
	}
	marshal, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(marshal))
}
