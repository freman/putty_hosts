//go:build !windows
// +build !windows

package putty_hosts

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// KnownHosts returns a ssh/knownhosts handler by by converting the putty for linux keys to a file - I was lazy
func KnownHosts() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	name := path.Join(home, ".putty", strings.ToLower("SshHostKeys"))
	kv := confToMap(name, " ")

	f, err := os.CreateTemp("", "knownhosts")
	if err != nil {
		return nil, err
	}

	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	for keyName, keyValue := range kv {
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

func confToMap(name, separator string) (kv map[string]string) {
	kv = make(map[string]string)
	file, err := os.Open(name)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()
		if s == "" {
			continue
		}
		ss := strings.Split(s, separator)
		v := ""
		if len(ss) > 1 {
			v = ss[1]
		}
		kv[ss[0]] = v
	}
	return
}
