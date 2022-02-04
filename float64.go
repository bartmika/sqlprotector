package sqlprotector

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"strconv"
)

// ProtectFloat64 represents the uint64 value that will get encrypted when the data is stored in the database and when we want to decrypt data from a database.
type ProtectFloat64 struct {
	// Plaintext data in use when your application fetches the data from the database; in addition, plaintext data gets encrypted when saved to the database.
	Plaintext float64
}

// Value implementing the driver.Valuer interface from the database/sql package and encrypts the outgoing sql column data.
func (ls ProtectFloat64) Value() (driver.Value, error) {
	s := fmt.Sprintf("%f", ls.Plaintext)
	ciphertext, err := encrypt(s)
	if err != nil {
		return nil, err
	}
	return driver.Value(ciphertext), nil
}

// Scan implements sql.Scanner interface from the database/sql package and decryptes incoming sql column data.
func (ls *ProtectFloat64) Scan(value interface{}) error {
	switch v := value.(type) {
	case string:
		s, err := decrypt(v)
		if err != nil {
			return err
		}
		floatNum, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		ls.Plaintext = floatNum
	case []byte:
		s, err := decrypt(string(v))
		if err != nil {
			return err
		}
		floatNum, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return err
		}
		ls.Plaintext = floatNum
	default:
		return fmt.Errorf("failed to scan type %+v for value", reflect.TypeOf(value))
	}
	return nil
}
