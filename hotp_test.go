package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const secret = "12345678901234567890"

func TestHotpEightDigits(t *testing.T) {
	var expectedCodes = map[uint64]string{
		0: "84755224",
		1: "94287082",
		2: "37359152",
		3: "26969429",
		4: "40338314",
		5: "68254676",
		6: "18287922",
		7: "82162583",
		8: "73399871",
		9: "45520489",
	}

	var counter uint64 = 10
	digits := 8

	for i := range counter {
		hotp := CreateHotp(secret, i, digits)

		code, err := hotp.Calculate()
		assert.Nil(t, err)

		assert.Equal(t, expectedCodes[i], code)
	}
}

func TestHotpSevenDigits(t *testing.T) {
	var expectedCodes = map[uint64]string{
		0: "4755224",
		1: "4287082",
		2: "7359152",
		3: "6969429",
		4: "0338314", // remove the leading zero since that is just formatting
		5: "8254676",
		6: "8287922",
		7: "2162583",
		8: "3399871",
		9: "5520489",
	}

	var counter uint64 = 10
	digits := 7

	for i := range counter {
		hotp := CreateHotp(secret, i, digits)

		code, err := hotp.Calculate()
		assert.Nil(t, err)

		assert.Equal(t, expectedCodes[i], code)
	}
}

func TestHotpSixDigits(t *testing.T) {
	var expectedCodes = map[uint64]string{
		0: "755224",
		1: "287082",
		2: "359152",
		3: "969429",
		4: "338314",
		5: "254676",
		6: "287922",
		7: "162583",
		8: "399871",
		9: "520489",
	}

	var counter uint64 = 10
	digits := 6

	for i := range counter {
		hotp := CreateHotp(secret, i, digits)

		code, err := hotp.Calculate()
		assert.Nil(t, err)

		assert.Equal(t, expectedCodes[i], code)
	}
}
