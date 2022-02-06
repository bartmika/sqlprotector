package sqlprotector

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"reflect"
)

// Nullable String that overrides sql.NullString
type NullString struct {
	sql.NullString
}

func MarshalJSONNullString(ns sql.NullString) ([]byte, error) {
	// Special thanks to https://gist.github.com/keidrun/d1b2791f840753e25070771b857af7ba
	if ns.Valid {
		return json.Marshal(ns.String)
	}
	return json.Marshal(nil)
}

func UnmarshalJSONNullString(data []byte) (sql.NullString, error) {
	// Special thanks to https://gist.github.com/keidrun/d1b2791f840753e25070771b857af7ba
	var ns sql.NullString
	var s *string
	if err := json.Unmarshal(data, &s); err != nil {
		return ns, err
	}
	if s != nil {
		ns.Valid = true
		ns.String = *s
	} else {
		ns.Valid = false
	}
	return ns, nil
}

// ProtectNullString represents the string value that will get encrypted when the data is stored in the database and when we want to decrypt data from a database.
type ProtectNullString struct {
	// Plaintext data in use when your application fetches the data from the database; in addition, plaintext data gets encrypted when saved to the database.
	Plaintext sql.NullString
}

// Value implementing the driver.Valuer interface from the database/sql package and encrypts the outgoing sql column data.
func (ls ProtectNullString) Value() (driver.Value, error) {
	bin, err := MarshalJSONNullString(ls.Plaintext)
	if err != nil {
		return nil, err
	}
	ciphertext, err := encrypt(string(bin))
	if err != nil {
		return nil, err
	}
	return driver.Value(ciphertext), nil
}

// Scan implements sql.Scanner interface from the database/sql package and decryptes incoming sql column data.
func (ls *ProtectNullString) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		s, err := decrypt(v)
		if err != nil {
			return err
		}
		ss, err := UnmarshalJSONNullString([]byte(s))
		if err != nil {
			return err
		}
		ls.Plaintext = sql.NullString{
			String: ss.String,
			Valid:  ss.Valid,
		}
	case []byte:
		s, err := decrypt(string(v))
		if err != nil {
			return err
		}
		ss, err := UnmarshalJSONNullString([]byte(s))
		if err != nil {
			return err
		}
		ls.Plaintext = sql.NullString{
			String: ss.String,
			Valid:  ss.Valid,
		}
	default:
		return fmt.Errorf("failed to scan type %+v for value", reflect.TypeOf(value))
	}
	return nil
}
