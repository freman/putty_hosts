# Putty Hosts

For another project I need to parse hosts to use with `golang.org/x/crypto/ssh`

In Windows, this is stored in the registry under `HKEY_CURRENT_USER\SoftWare\SimonTatham\PuTTY\SshHostKeys` where the key name is the algorithum, port and host and the actual public key is stored as simply really big numbers.

```
[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys]
"ssh-ed25519@22:10.10.0.1"="0x32d013e2996f93c5f5cec2ab3aac303434f31775aababf3ea342e1227ab4ac36,0x45d63b169d50b797498eb035b1055c6e83e36f21b1da140c3ed3caa60fa4d866"
```

In Linux (Unix, etc), this is stored in `~/.putty/sshhostkeys` in basically the same format but space deliniated

```
ssh-ed25519@22:10.10.0.1 0x32d013e2996f93c5f5cec2ab3aac303434f31775aababf3ea342e1227ab4ac36,0x45d63b169d50b797498eb035b1055c6e83e36f21b1da140c3ed3caa60fa4d866
```

Due to the way `golang.org/x/crypto/ssh` handles it's keys, it's just simpler to convert to openssh compatible known_hosts lines and call it a day.
