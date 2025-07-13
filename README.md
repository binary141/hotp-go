# HMAC-Based One-Time Password (HOTP) Algorigthm

## What is this?
A Golang implementation of [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226). Includes helpers that aren't defined in the RFC to make it easier to use / manage in code.

## Install
Requires >=1.24.2

```sh
go get github.com/binary141/hotp-go@v1.0.0
```
## Usage
```golang
package main

import (
	"fmt"

	hotp "github.com/binary141/hotp-go"
)

func main() {
	encodedSecret := "UMMZWVYTALVNLF2F2E46CGLB273LSV67"

	var counter uint64 = 0
	digits := 6

	secret, err := DecodeSecret(encodedSecret)
	if err != nil {
		panic(err)
	}

	otp := CreateHotp(secret, counter, digits)

	code, err := otp.Calculate()
	if err != nil {
		panic(err)
	}

	fmt.Println(code)

	validated, err := otp.Validate(289757)
	if err != nil {
		panic(err)
	}

	fmt.Println(validated) // -> false

	err = otp.SetLookAheadWindow(1)
	if err != nil {
		panic(err)
	}

	validated, err = otp.Validate(289757)
	if err != nil {
		panic(err)
	}

	fmt.Println(validated) // -> true
}
```

## Testing
```sh
go test
```

