package main

import (
	"strings"
	"testing"
)

// The client id is checked locally so a pasted account name fails with a clear message instead of the API's indistinguishable "invalid credentials". A legacy 24-hex id must fail the same way, because the API no longer issues one.
func TestAPIClient_ClientIDMustBeAUUID(t *testing.T) {
	t.Setenv("ARTEFACTFLOW_CLIENT_SECRET", "afsa_test-client-secret")

	for _, id := range []string{"0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0", "0198E2C3-9A21-7B8E-90F5-6C1D4E2A83B0"} {
		if _, err := apiClient("https://api.example.test", id); err != nil {
			t.Errorf("client id %q should be accepted: %v", id, err)
		}
	}
	for _, id := range []string{"ci-publisher", "507f191e810c19729de860ed", "0198e2c39a217b8e90f56c1d4e2a83b0"} {
		_, err := apiClient("https://api.example.test", id)
		if err == nil || !strings.Contains(err.Error(), "a UUID") {
			t.Errorf("client id %q: want a UUID error, got %v", id, err)
		}
	}
}
