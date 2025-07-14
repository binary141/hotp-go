package hotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"os"
)

const (
	maxLookAheadSize = 10
	SHA1             = HashFunc("sha1")
	SHA256           = HashFunc("sha256")
	SHA512           = HashFunc("sha512")
)

type HashFunc string

var (
	issuer = ""
)

func init() {
	envIssuer := os.Getenv("ISSUER")
	if envIssuer == "" {
		issuer = "hotp"
	}

	issuer = envIssuer
}

type Hotp struct {
	secret          string
	counter         uint64
	digits          int
	lookAheadWindow int
	hashFunc        HashFunc
	hasher          func() hash.Hash
}

func dynamicTruncate(secret string, counter uint64, hasher func() hash.Hash) (int32, error) {
	hmac := hmac.New(hasher, []byte(secret))

	// a uint64 is 8 bytes
	bigEndCount := make([]byte, 8)
	binary.BigEndian.PutUint64(bigEndCount, counter)

	_, err := hmac.Write(bigEndCount)
	if err != nil {
		return -1, err
	}

	hash := hmac.Sum(nil)

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
func CalculateCode(secret string, counter uint64, digits int, hasher func() hash.Hash) (string, error) {
	Sbits, err := dynamicTruncate(secret, counter, hasher)
	if err != nil {
		return "", err
	}

	code := int(Sbits % int32(math.Pow10(digits)))

	return formatCode(code, digits), nil
}

// can be used directly without needing to construct an Hotp object
func Validate(secret string, counter uint64, digits int, code int, hasher func() hash.Hash) (bool, error) {
	correctCode, err := CalculateCode(secret, counter, digits, hasher)
	if err != nil {
		return false, err
	}

	formattedCode := formatCode(code, digits)
	fmt.Printf("%s -> %s -> %d\n", formattedCode, correctCode, counter)

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
		hashFunc:        SHA1,
		hasher:          sha1.New,
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

func (hotp *Hotp) SetHashFunc(hashFunc HashFunc) error {
	switch hashFunc {
	case SHA1:
		hotp.hashFunc = SHA1
		hotp.hasher = sha1.New
		return nil
	case SHA256:
		hotp.hashFunc = SHA256
		hotp.hasher = sha256.New
		return nil
	case SHA512:
		hotp.hashFunc = SHA512
		hotp.hasher = sha512.New
		return nil
	default:
		return fmt.Errorf("hashing function '%s' not implemtented", hashFunc)
	}
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
	validated, err := Validate(hotp.secret, hotp.counter, hotp.digits, code, hotp.hasher)
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

		newCounter := hotp.counter + i
		validated, err := Validate(hotp.secret, newCounter, hotp.digits, code, hotp.hasher)
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
	return CalculateCode(hotp.secret, hotp.counter, hotp.digits, hotp.hasher)
}

func (hotp Hotp) GenerateOtpAuth() string {
	params := hotp.GenerateOtpAuthParams()

	return fmt.Sprintf("otpauth://hotp/%s", params)
}

// generates a random []byte of length. Note 10-20 is generally secure for hotp
func GenerateSecret(length int) []byte {
	secret := make([]byte, length)

	// rand.Read will never return an error
	_, _ = rand.Read(secret)

	return secret
}

// returns a string that is base32 encoded
func EncodeSecret(secret []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return encoded
}

// returns a string that is base32 decoded
func DecodeSecret(secret string) (string, error) {
	decoded, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func (hotp Hotp) GenerateOtpAuthParams() string {
	return fmt.Sprintf("%s?secret=%s&algorithm=%s&counter=%d",
		issuer,
		EncodeSecret([]byte(hotp.secret)),
		hotp.hashFunc,
		hotp.counter)
}
