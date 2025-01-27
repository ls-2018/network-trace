package nft

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestT(t *testing.T) {
	file, err := ioutil.ReadFile("../../test/resources/cilium.json")
	if err != nil {
		t.Fatal(err)
	}

	var allRules All
	if err := json.Unmarshal(file, &allRules); err != nil {
		fmt.Printf("Error unmarshaling JSON: %v\n", err)
		return
	}

	marshaledData, err := json.MarshalIndent(allRules, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	fmt.Println(string(marshaledData))
}
