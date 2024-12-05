//go:build windows
// +build windows

package putty_hosts

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/windows/registry"
)

// KnownHosts returns a ssh/knownhosts handler by by converting the putty registry keys to a file - I was lazy
func KnownHosts() (ssh.HostKeyCallback, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\SimonTatham\PuTTY\SshHostKeys`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	keyNames, err := k.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	f, err := os.CreateTemp("", "knownhosts")
	if err != nil {
		return nil, err
	}

	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	for _, keyName := range keyNames {
		keyValue, _, err := k.GetStringValue(keyName)
		if err != nil {
			// I dunno...
			fmt.Println("error reading key from registry", err.Error())
			continue
		}

		sshKey, err := ToSSH(keyName, keyValue)
		if err != nil {
			// again dunno...
			fmt.Println("error converting key to openssh format", err.Error())
			continue
		}

		if _, err := f.WriteString(sshKey + "\n"); err != nil {
			// More of the above"
			fmt.Println("error writing key to file", err.Error())
			continue
		}
	}

	f.Sync()

	return knownhosts.New(f.Name())
}
