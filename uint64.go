package sqlprotector

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"strconv"
)

// ProtectUint64 represents the uint64 value that will get encrypted when the data is stored in the database and when we want to decrypt data from a database.
type ProtectUint64 struct {
	// Plaintext data in use when your application fetches the data from the database; in addition, plaintext data gets encrypted when saved to the database.
	Plaintext uint64
}

// Value implementing the driver.Valuer interface from the database/sql package and encrypts the outgoing sql column data.
func (ls ProtectUint64) Value() (driver.Value, error) {
	str := strconv.FormatUint(ls.Plaintext, 10)
	ciphertext, err := encrypt(str)
	if err != nil {
		return nil, err
	}
	return driver.Value(ciphertext), nil
}

// Scan implements sql.Scanner interface from the database/sql package and decryptes incoming sql column data.
func (ls *ProtectUint64) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		s, err := decrypt(v)
		if err != nil {
			return err
		}
		number, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		ls.Plaintext = number
	case []byte:
		s, err := decrypt(string(v))
		if err != nil {
			return err
		}
		number, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		ls.Plaintext = number
	default:
		return fmt.Errorf("failed to scan type %+v for value", reflect.TypeOf(value))
	}
	return nil
}
