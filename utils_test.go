package sqlprotector

import (
	"reflect"
	"testing"
)

func TestSetAndGetSQLPassphrase(t *testing.T) {
	// CASE 1: Error
	expectedPassphrase := []byte("lalalalala")
	err := SetSQLProtectorPassphrase(expectedPassphrase)
	if err == nil {
		t.Errorf("Expected an error but got none!")
	}

	// CASE 2: Success
	expectedPassphrase = []byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa")
	err = SetSQLProtectorPassphrase(expectedPassphrase)
	if err != nil {
		t.Errorf("Expected no error but error: %s", err.Error())
	}

	// Get our entry key.
	actualPassphrase := GetSQLProtectorPassphrase()
	if reflect.DeepEqual(actualPassphrase, expectedPassphrase) == false {
		t.Errorf("Incorrect entry key, got %v but was expecting %v", actualPassphrase, expectedPassphrase)
	}
}

func TestAESEncrypt(t *testing.T) {
	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
	expectedPT := "Hello World"

	actualCT, err := encrypt(expectedPT)
	if err != nil {
		t.Errorf("Expected no error but error: %s", err.Error())
	}
	if actualCT == "" {
		t.Error("Expected not empty ciphertext but empty eiphertext!")
	}

}
