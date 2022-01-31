package sqlprotector

import (
	"database/sql/driver"
	"fmt"
	"reflect"
)

// ProtectString represents the string value that will get encrypted when the data is stored in the database and when we want to decrypt data from a database.
type ProtectString struct {
	// Plaintext data in use when your application fetches the data from the database; in addition, plaintext data gets encrypted when saved to the database.
	Plaintext string
}

// Value implementing the driver.Valuer interface from the database/sql package and encrypts the outgoing sql column data.
func (ls ProtectString) Value() (driver.Value, error) {
	ciphertext, err := encrypt(ls.Plaintext)
	if err != nil {
		return nil, err
	}
	return driver.Value(ciphertext), nil
}

// Scan implements sql.Scanner interface from the database/sql package and decryptes incoming sql column data.
func (ls *ProtectString) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		s, err := decrypt(v)
		if err != nil {
			return err
		}
		ls.Plaintext = s
	case []byte:
		s, err := decrypt(string(v))
		if err != nil {
			return err
		}
		ls.Plaintext = string(s)
	default:
		return fmt.Errorf("failed to scan type %+v for value", reflect.TypeOf(value))
	}
	return nil
}
