package op

import (
	"encoding/json"
	"errors"
	"github.com/go-jose/go-jose/v3"
	"oidc/crypto"
)

type Crypto interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
	Sign(object interface{}, signer jose.Signer) (string, error)
}

type aesCrypto struct {
	key string
}

func (c *aesCrypto) Sign(object interface{}, signer jose.Signer) (string, error) {
	payload, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	return SignPayload(payload, signer)
}

func SignPayload(payload []byte, signer jose.Signer) (string, error) {
	if signer == nil {
		return "", errors.New("missing signer")
	}

	result, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return result.CompactSerialize()
}

func NewAESCrypto(key [32]byte) Crypto {
	return &aesCrypto{key: string(key[:32])}
}

func (c *aesCrypto) Encrypt(s string) (string, error) {
	return crypto.EncryptAES(s, c.key)
}

func (c *aesCrypto) Decrypt(s string) (string, error) {
	return crypto.DecryptAES(s, c.key)
}
