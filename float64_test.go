package sqlprotector

import (
	"log"
	"testing"
)

func TestProtectFloat64Value(t *testing.T) {
	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
	pt := ProtectFloat64{Plaintext: 123.456}
	ct, err := pt.Value()
	if err != nil {
		t.Error(err)
	}
	if ct == nil {
		t.Errorf("Expected no nills but got a nll")
	}
	log.Println(ct)
}

func TestProtectFloat64Scan(t *testing.T) {
	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
	var pt ProtectFloat64
	var expected float64 = 123.456

	// CASE 1: String
	ct := "yy9jE+QDGI8fc1HyA3qqASFIlJqrQTW7HEYsQs5REKrWIFXxzK8="
	err := pt.Scan(ct)
	if err != nil {
		t.Error(err)
	}
	if pt.Plaintext != expected {
		t.Errorf("Incorrect decryption, got %v but was expecting %v", pt.Plaintext, expected)
	}

	// CASE 2: []byte
	ct2 := []byte("yy9jE+QDGI8fc1HyA3qqASFIlJqrQTW7HEYsQs5REKrWIFXxzK8=")
	err = pt.Scan(ct2)
	if err != nil {
		t.Error(err)
	}
	if pt.Plaintext != expected {
		t.Errorf("Incorrect decryption, got %v but was expecting %v", pt.Plaintext, expected)
	}

	// CASE 3: Error
	ct3 := false
	err = pt.Scan(ct3)
	if err == nil {
		t.Errorf("Expected a nill error.")
	}
}

// func TestProtectFloat64ScanForErrors(t *testing.T) {
// 	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
// 	var pt ProtectFloat64
//
// 	// CASE 1:
// 	ct := "BAD-CIPHER_TEXT"
// 	err := pt.Scan(ct)
// 	if err == nil {
// 		t.Errorf("Exptect `%s` error but got nothing!", "illegal base64 data at input byte 3")
// 	}
//
// 	// CASE 2:
// 	ct2 := base64.StdEncoding.EncodeToString([]byte("BAD-CIPHER_TEXT"))
// 	err = pt.Scan(string(ct2))
// 	if err == nil {
// 		t.Errorf("Expected `%s` error but got nothing!", "cipher: message authentication failed")
// 	}
//
// 	// CASE 3:
// 	ct3 := base64.StdEncoding.EncodeToString([]byte("BAD-CIPHER_TEXT"))
// 	err = pt.Scan([]byte(ct3))
// 	if err == nil {
// 		t.Errorf("Expected `%s` error but got nothing!", "cipher: message authentication failed")
// 	}
// }
