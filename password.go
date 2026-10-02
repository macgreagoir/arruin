package main

import (
	"crypto/rand"
	"math/big"
)

const generatedPasswordLength = 12

// passwordCharset is printable ASCII excluding space: '!' (0x21) through
// '~' (0x7e), 94 characters covering letters, digits, and every standard
// punctuation/symbol. Space (and every other whitespace character) is
// deliberately excluded -- db.go's entry format is a single
// whitespace-separated line, parsed with strings.Fields, so a password
// containing whitespace would silently corrupt the stored entry.
var passwordCharset = func() []byte {
	cs := make([]byte, 0, '~'-'!'+1)
	for c := byte('!'); c <= '~'; c++ {
		cs = append(cs, c)
	}
	return cs
}()

// generatePassword returns a cryptographically random password of length n
// drawn from passwordCharset.
func generatePassword(n int) (string, error) {
	charsetSize := big.NewInt(int64(len(passwordCharset)))
	pw := make([]byte, n)
	for i := range pw {
		idx, err := rand.Int(rand.Reader, charsetSize)
		if err != nil {
			return "", err
		}
		pw[i] = passwordCharset[idx.Int64()]
	}
	return string(pw), nil
}
