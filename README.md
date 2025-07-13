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

## Envs

| Key      | Value Type | Example Value     |
|----------|------------|-------------------|
| `ISSUER` | `string`   | `"MyApplication"` |

**Description:**  
The `ISSUER` is a string that identifies the service or provider issuing the HOTP/TOTP codes. 
It is used in OTP provisioning URIs (e.g., `otpauth://...`) and typically displayed by authenticator apps like Google Authenticator or Authy as the account "provider" name.

## Testing
```sh
go test
```

