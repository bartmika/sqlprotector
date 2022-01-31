package sqlprotector

import (
	"reflect"
	"testing"
)

func TestSetAndGetEntryKey(t *testing.T) {
	// CASE 1: Error
	expectedEntryKey := []byte("lalalalala")
	err := SetSQLProtectorPassphrase(expectedEntryKey)
	if err == nil {
		t.Errorf("Expected an error but got none!")
	}

	// CASE 2: Success
	expectedEntryKey = []byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa")
	err = SetSQLProtectorPassphrase(expectedEntryKey)
	if err != nil {
		t.Errorf("Expected no error but error: %s", err.Error())
	}

	// Get our entry key.
	actualEntryKey := GetSQLProtectorPassphrase()
	if reflect.DeepEqual(actualEntryKey, expectedEntryKey) == false {
		t.Errorf("Incorrect entry key, got %v but was expecting %v", actualEntryKey, expectedEntryKey)
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
