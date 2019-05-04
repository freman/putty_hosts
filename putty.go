package putty_hosts

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

func ParseKeyName(keyName string) (algo, host string) {
	atIndex := strings.Index(keyName, "@")
	algo = keyName[:atIndex]

	switch algo {
	case "dss":
		algo = ssh.KeyAlgoDSA
	case "rsa2":
		algo = ssh.KeyAlgoRSA
	}

	host = keyName[atIndex+1:]
	for i, r := range host {
		if r < 48 || r > 58 {
			break
		}
		if r == 58 {
			if i > 0 {
				if host[0:i] == "22" {
					return algo, host[i+1:]

				}
				return algo, host[i+1:] + ":" + host[0:i]
			}
			break
		}
	}

	return algo, host
}

// ToSSH will convert a putty registry key/value combination into a known_hosts entry.
func ToSSH(keyName, keyValue string) (result string, err error) {
	algo, host := ParseKeyName(keyName)
	values := strings.Split(keyValue, ",")

	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.BigEndian, uint32(len(algo)))
	buf.Write([]byte(algo))

	switch algo {
	case ssh.KeyAlgoDSA, ssh.KeyAlgoRSA:
		err = encodeDSARSA(values, buf)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		err = encodeECDSA(values, buf)
	case ssh.KeyAlgoED25519:
		err = encodeED25519(values, buf)
	}

	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s %s %s", host, algo, base64.StdEncoding.EncodeToString(buf.Bytes())), err
}

func encodeECDSA(values []string, w io.Writer) error {
	if len(values) != 3 {
		return errors.New("putty: invalid number of values for ECDSA key")
	}

	var (
		data []byte
		x, y *big.Int
		ok   bool
	)

	if x, ok = new(big.Int).SetString(values[1][2:], 16); !ok {
		return errors.New("putty: X is invalid")
	}

	if y, ok = new(big.Int).SetString(values[2][2:], 16); !ok {
		return errors.New("putty: Y is invalid")
	}

	binary.Write(w, binary.BigEndian, uint32(len(values[0])))
	w.Write([]byte(values[0]))

	switch values[0] {
	case "nistp256":
		data = elliptic.Marshal(elliptic.P256(), x, y)
	case "nistp384":
		data = elliptic.Marshal(elliptic.P384(), x, y)
	case "nistp521":
		data = elliptic.Marshal(elliptic.P521(), x, y)
	default:
		return errors.New("putty: unknown curve")
	}

	binary.Write(w, binary.BigEndian, uint32(len(data)))
	_, err := w.Write(data)

	return err
}

func encodeED25519(values []string, w io.Writer) error {
	if len(values) != 2 {
		return errors.New("putty: invalid number of values for ED25519 key")
	}

	n, ok := new(big.Int).SetString(values[1][2:], 16)
	if !ok {
		return errors.New("putty: input is invalid")
	}

	binary.Write(w, binary.BigEndian, uint32(len(n.Bytes())))

	b := n.Bytes()
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}

	_, err := w.Write(b)

	return err
}

func encodeDSARSA(values []string, w io.Writer) error {
	for _, value := range values {
		n, ok := new(big.Int).SetString(value[2:], 16)
		if !ok {
			return errors.New("putty: input is invalid")
		}
		b := n.Bytes()
		if b[0]&0x80 == 0x80 {
			b = append([]byte{0}, b...)
		}
		binary.Write(w, binary.BigEndian, uint32(len(b)))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
	}
	return nil
}
