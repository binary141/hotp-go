package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

const maxLookAheadSize = 10

type Hotp struct {
	secret          string
	counter         uint64
	digits          int
	lookAheadWindow int
	hashFunc        func() hash.Hash
}

func dynamicTruncate(secret string, counter uint64, hashFunc func() hash.Hash) (int32, error) {
	hasher := hmac.New(hashFunc, []byte(secret))

	// a uint64 is 8 bytes
	bigEndCount := make([]byte, 8)
	binary.BigEndian.PutUint64(bigEndCount, counter)

	_, err := hasher.Write(bigEndCount)
	if err != nil {
		return -1, err
	}

	hash := hasher.Sum(nil)

	offsetBits := hash[0 : 19+1]

	offset := int(offsetBits[19]) & 0xf
	if offset < 0 || offset > 15 {
		panic(fmt.Sprintf("offset has to be >= 0 and <= 15. Got: %d", offset))
	}

	P := hash[offset : offset+3+1]

	a := int32(P[0] & 0x7f)
	b := int32(P[1] & 0xff)
	c := int32(P[2] & 0xff)
	d := int32(P[3] & 0xff)

	return int32(a<<24 | b<<16 | c<<8 | d), nil
}

func formatCode(code int, digits int) string {
	// pad out the string if the leading number(s) are a 0
	format := fmt.Sprintf(`%%0%dd`, digits)

	return fmt.Sprintf(format, code)
}

// can be used directly without needing to construct an Hotp object
func CalculateCode(secret string, counter uint64, digits int, hashFunc func() hash.Hash) (string, error) {
	Sbits, err := dynamicTruncate(secret, counter, hashFunc)
	if err != nil {
		return "", err
	}

	code := int(Sbits % int32(math.Pow10(digits)))

	return formatCode(code, digits), nil
}

// can be used directly without needing to construct an Hotp object
func Validate(secret string, counter uint64, digits int, code int, hashFunc func() hash.Hash) (bool, error) {
	correctCode, err := CalculateCode(secret, counter, digits, hashFunc)
	if err != nil {
		return false, err
	}

	formattedCode := formatCode(code, digits)

	return correctCode == formattedCode, nil
}

/*
** creates an hotp object with a default hashing algorithm of SHA-1,
** and a default look ahead window of 0
 */
func CreateHotp(secret string, counter uint64, digits int) Hotp {
	return Hotp{
		secret:          secret,
		counter:         counter,
		digits:          digits,
		lookAheadWindow: 0,
		hashFunc:        sha1.New,
	}
}

func (hotp *Hotp) SetLookAheadWindow(size int) error {
	if size > maxLookAheadSize {
		return fmt.Errorf("size cannot be greater than %d for look ahead window. Please set it to a smaller value", maxLookAheadSize)
	}

	hotp.lookAheadWindow = size
	return nil
}

func (hotp Hotp) GetCounter() uint64 {
	return hotp.counter
}

func (hotp *Hotp) SetHashFunc(hashFunc func() hash.Hash) {
	hotp.hashFunc = hashFunc
}

func (hotp *Hotp) IncrementCounter() {
	hotp.counter += 1
}

func (hotp *Hotp) SetCounter(counter uint64) {
	hotp.counter = counter
}

/*
* Validate will take a code, and check to see if it matches the output of CalculateCode
* The lookAheadWindow field is used here to determine if the client is out of sync with the server,
* and if necessary, alter the counter on the hotp to match. This is described in rfc4226 section 7.4
* Upon success, increments the counter
 */
func (hotp *Hotp) Validate(code int) (bool, error) {
	validated, err := Validate(hotp.secret, hotp.counter, hotp.digits, code, hotp.hashFunc)
	if err != nil {
		return false, err
	}

	if validated {
		hotp.IncrementCounter()
		return true, nil
	}

	if !validated && (hotp.lookAheadWindow == 0) {
		return false, nil
	}

	for i := range uint64(hotp.lookAheadWindow) {
		// make i one based to adjust the counter upon success
		i += 1

		validated, err := Validate(hotp.secret, hotp.counter+i, hotp.digits, code, hotp.hashFunc)
		if err != nil {
			return false, err
		}

		if validated {
			// resynchronize the counter on the object to get it back with the client
			hotp.counter += i
			return true, nil
		}
	}

	return false, nil
}

func (hotp Hotp) Calculate() (string, error) {
	return CalculateCode(hotp.secret, hotp.counter, hotp.digits, hotp.hashFunc)
}
