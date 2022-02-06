package sqlprotector

import (
	"database/sql"
	"encoding/base64"
	"testing"
)

func TestProtectNullStringValue(t *testing.T) {
	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
	pt := ProtectNullString{Plaintext: sql.NullString{String: "Hello World", Valid: true}}
	ct, err := pt.Value()
	if err != nil {
		t.Error(err)
	}
	if ct == nil {
		t.Errorf("Expected no nills but got a nll")
	}
}

func TestProtectNullStringScan(t *testing.T) {
	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
	var pt ProtectNullString
	expected := sql.NullString{String: "Hello World", Valid: true}

	// CASE 1: NullString
	ct := "8k3UNi/LRG3ImI1FmGc6ZMdInofK0O5EGzidR/+B7kTLBA+IZneOJtA="
	err := pt.Scan(ct)
	if err != nil {
		t.Error(err)
	}

	if pt.Plaintext != expected {
		t.Errorf("Incorrect decryption, got %v but was expecting %v", pt.Plaintext, expected)
	}

	// CASE 2: []byte
	ct2 := []byte("8k3UNi/LRG3ImI1FmGc6ZMdInofK0O5EGzidR/+B7kTLBA+IZneOJtA=")
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

func TestProtectNullStringScanForErrors(t *testing.T) {
	SetSQLProtectorPassphrase([]byte("sdfdsfedrdsfsdfsdfazfasfasdfsdfa"))
	var pt ProtectNullString

	// CASE 1:
	ct := "BAD-CIPHER_TEXT"
	err := pt.Scan(ct)
	if err == nil {
		t.Errorf("Exptect `%s` error but got nothing!", "illegal base64 data at input byte 3")
	}

	// CASE 2:
	ct2 := base64.StdEncoding.EncodeToString([]byte("BAD-CIPHER_TEXT"))
	err = pt.Scan(string(ct2))
	if err == nil {
		t.Errorf("Expected `%s` error but got nothing!", "cipher: message authentication failed")
	}

	// CASE 3:
	ct3 := base64.StdEncoding.EncodeToString([]byte("BAD-CIPHER_TEXT"))
	err = pt.Scan([]byte(ct3))
	if err == nil {
		t.Errorf("Expected `%s` error but got nothing!", "cipher: message authentication failed")
	}
}
