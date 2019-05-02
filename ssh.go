package putty_hosts

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"net"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

func ToPutty(knownHost string) (keyName, keyValue string, err error) {
	_, hosts, pubkey, _, _, err := ssh.ParseKnownHosts([]byte(knownHost))
	if err != nil {
		panic(err)
	}

	host, port, _ := net.SplitHostPort(hosts[0])
	if host == "" {
		host = hosts[0]
	}

	if port == "" {
		port = "22"
	}

	if cpk, isa := pubkey.(ssh.CryptoPublicKey); isa {
		acpt := cpk.CryptoPublicKey()

		switch v := acpt.(type) {
		case *dsa.PublicKey:
			keyName = "dss@" + port + ":" + host
			keyValue = maker(v.P, v.Q, v.G, v.Y)
		case *rsa.PublicKey:
			keyName = "rsa2@" + port + ":" + host
			keyValue = maker(big.NewInt(int64(v.E)), v.N)
		case *ecdsa.PublicKey:
			nist := fmt.Sprintf("nistp%d", v.Params().BitSize)
			keyName = "ecdsa-sha2-" + nist + "@" + port + ":" + host
			keyValue = nist + "," + maker(v.X, v.Y)
		case ed25519.PublicKey:
			// Flip endian. ed25519 is little endian, we want big for the math
			b := make([]byte, len(v))
			copy(b, v)
			for i := 0; i < len(b)/2; i++ {
				b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
			}

			n := func() *big.Int { return new(big.Int) }

			one := big.NewInt(1)
			two := big.NewInt(2)
			three := big.NewInt(3)
			four := big.NewInt(4)
			eight := big.NewInt(8)
			nineteen := big.NewInt(19)
			two55 := big.NewInt(255)

			y := n().SetBytes(b)
			xP := n().Rsh(y, 255)
			y = n().AndNot(y, n().Lsh(one, 255))

			p := n().Sub(n().Exp(two, two55, nil), nineteen)
			xx, _ := n().SetString("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16)
			xx.Mod(xx.Mul(n().Sub(n().Mul(y, y), one), xx.Exp(xx.Add(xx.Mul(xx.Mul(xx, y), y), one), n().Sub(p, two), p)), p)

			x := n().Exp(xx, n().Div(n().Add(p, three), eight), p)
			if n().Exp(x, two, p).Cmp(xx) != 0 {
				x = x.Mod(x.Mul(x, n().Exp(two, n().Div(n().Sub(n().Set(p), one), four), p)), p)

				if n().Exp(x, two, p).Cmp(xx) != 0 {
					panic("assertion failed")
				}
			}

			if n().Mod(x, two).Cmp(xP) != 0 {
				x = p.Sub(p, x)
			}

			keyName = "ssh-ed25519@" + port + ":" + host
			keyValue = maker(x, y)
		}
	}
	return keyName, keyValue, nil
}

func maker(is ...*big.Int) string {
	var b strings.Builder
	for i, ii := range is {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "0x%x", ii)
	}
	return b.String()
}
