# sqlprotector
[![GoDoc](https://godoc.org/github.com/gomarkdown/markdown?status.svg)](https://pkg.go.dev/github.com/bartmika/sqlprotector)
[![Go Report Card](https://goreportcard.com/badge/github.com/bartmika/sqlprotector)](https://goreportcard.com/report/github.com/bartmika/sqlprotector)

A go package to add support for **data at rest encryption** to Golang's standard library [`database/sql`](https://pkg.go.dev/database/sql).

## Installation

In your Golang project, please run:

```
go get github.com/bartmika/sqlprotector
```

## Documentation

All [documentation](https://pkg.go.dev/github.com/bartmika/sqlprotector) can be found here.

## Contributing

Found a bug? Want a feature to improve your developer experience? Please create an [issue](https://github.com/bartmika/sqlprotector/issues).

## License
Made with ❤️ by [Bartlomiej Mika](https://bartlomiejmika.com).   
The project is licensed under the [ISC License](LICENSE).

Resource used:

* [__How We Encrypt Data in MySQL With Go__ By Baron Schwartz](https://orangematter.solarwinds.com/2017/07/31/how-we-encrypt-data-in-mysql-with-go/) helped me understand the overall big picture with what is involved with setting up your own data at rest encryption with Golang.
* [__Built In Interfaces__ by Jason Moiron](http://jmoiron.net/blog/built-in-interfaces/) help understand how we utilize the [`sql.Scanner`](https://pkg.go.dev/database/sql#Scanner) and [`driver.Valuer`](https://cs.opensource.google/go/go/+/master:src/database/sql/driver/types.go;l=39?q=valuer&sq=&ss=go%2Fgo) interfaces inside the go packages [database/sql](https://pkg.go.dev/database/sql) to write our own custom functionality.
* [__Securing Information in Database using Data Encryption (written in Go)__ by Purnaresa Yuliartanto](https://medium.com/swlh/securing-information-in-database-using-data-encryption-written-in-go-4b2754214050) help understand how to do encryption and decryption.
* [__go-cryptkeeper__ by Zach Auclair](https://github.com/blaskovicz/go-cryptkeeper) is a go package which implemented data at rest encryption utilizing the [`sql.Scanner`](https://pkg.go.dev/database/sql#Scanner) and [`driver.Valuer`](https://cs.opensource.google/go/go/+/master:src/database/sql/driver/types.go;l=39?q=valuer&sq=&ss=go%2Fgo) interfaces inside the go packages [database/sql](https://pkg.go.dev/database/sql) to write our own custom functionality.
