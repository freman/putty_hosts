package putty_hosts_test

import (
	"fmt"
	"testing"

	"github.com/abakum/putty_hosts"
)

func TestToPutty(t *testing.T) {
	t.Parallel()

	tests := [][]string{{
		"10.10.0.1 ssh-dss AAAAB3NzaC1kc3MAAACBAIHd6qN0gX53EZtU6kZKYHroTTCjphQrxiTjH3WpE6c6kDrGwsf4bsXvzcM14RKyJ5KpwD4rJVS6Dime+DvaH/rJ3r6lYWmihHi0+8YqHnQ18s36TPKER/kRU/7cCo98rxFGgG48C66l8FnOj9gkLki4jwjMYCtff4KTrde6posDAAAAFQD0mkDkEwxoSmi7BkljeROClClltwAAAIAFYBDlVCFkJ/KG4mGUS3fpNbPv6QlsFIMkv0YIoU9QfbUCR7QCUJfYjkH7iBIF/WR/BfRI/lf4gEsuk/7rF0+Z8xbbs6SXy5j6VHuyKouqnf+dUn5Xf71Pznxs5MpjZM0Z0ODxDDqQv9hwGEYqTFQ7A/gAmlIWPwv3AtorvOCVlwAAAIBIRiEtnyzBlx53rqhnwK6Trs2ZV9jOEq/keI69mwNeMSZUTzAl3R3GUEGUFL/buhxVX0+OJTK6KcWPHUTSrSAnZKR/0+0NPPTmjtDG5QkwYf6jvUz/otUlKhXZIWNgUL5C8NwavCClv83sT3JtRRQXQC1H55/7zSLhrQYQiqSOXQ==",
		"dss@22:10.10.0.1",
		"0x81ddeaa374817e77119b54ea464a607ae84d30a3a6142bc624e31f75a913a73a903ac6c2c7f86ec5efcdc335e112b22792a9c03e2b2554ba0e299ef83bda1ffac9debea56169a28478b4fbc62a1e7435f2cdfa4cf28447f91153fedc0a8f7caf1146806e3c0baea5f059ce8fd8242e48b88f08cc602b5f7f8293add7baa68b03,0xf49a40e4130c684a68bb064963791382942965b7,0x56010e554216427f286e261944b77e935b3efe9096c148324bf4608a14f507db50247b4025097d88e41fb881205fd647f05f448fe57f8804b2e93feeb174f99f316dbb3a497cb98fa547bb22a8baa9dff9d527e577fbd4fce7c6ce4ca6364cd19d0e0f10c3a90bfd87018462a4c543b03f8009a52163f0bf702da2bbce09597,0x4846212d9f2cc1971e77aea867c0ae93aecd9957d8ce12afe4788ebd9b035e3126544f3025dd1dc650419414bfdbba1c555f4f8e2532ba29c58f1d44d2ad202764a47fd3ed0d3cf4e68ed0c6e5093061fea3bd4cffa2d5252a15d921636050be42f0dc1abc20a5bfcdec4f726d451417402d47e79ffbcd22e1ad06108aa48e5d",
	}, {
		"10.10.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjYsTtqSF8DAZ0OuGa5z5NUTYsxsbVGnVKiyc1kg9jQPuFW1RpkTReUroCS7LzcIanwA72HcZXt8XudBRGIZE9hIFqhtRfjxpORHHKtE1Qv36DtamoOcRytAPse+QkDN7F8iBOK5tjge0S/nUNqrSWCGRJRAzOPcHksKtdqHpgtkry3GYf9sJgyWufCV4K1nD3yKSv9ZIdhpHAXO9Lkdhl+CQz9PripKz4FmD596ksGyIwzUDqyEllTHLmxs0J9ZAkvTqgRbEzLVe5xijsbg271iJT7gg7ig1uA3T+fHO3vgwSghwWMnlqDw/tNuArGmU77Ms6zf0jUkhtsHWKadA9",
		"rsa2@22:10.10.0.1",
		"0x10001,0xa362c4eda9217c0c06743ae19ae73e4d51362cc6c6d51a754a8b2735920f6340fb855b546991345e52ba024bb2f37086a7c00ef61dc657b7c5ee74144621913d84816a86d45f8f1a4e4471cab44d50bf7e83b5a9a839c472b403ec7be4240cdec5f2204e2b9b6381ed12fe750daab496086449440cce3dc1e4b0ab5da87a60b64af2dc661ff6c260c96b9f095e0ad670f7c8a4aff5921d8691c05cef4b91d865f82433f4fae2a4acf81660f9f7a92c1b2230cd40eac849654c72e6c6cd09f59024bd3aa045b1332d57b9c628ec6e0dbbd62253ee083b8a0d6e0374fe7c73b7be0c12821c1632796a0f0fed36e02b1a653beccb3acdfd2352486db0758a69d03d",
	}, {
		"10.10.0.1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBECoklboxwwp8qryWOHCFcnzzzu2iFO/EnQ67iUDSC7pOttDZgnMI+skoYT3NioZaRguy3XieRCyZX0syEA9oT0=",
		"ecdsa-sha2-nistp256@22:10.10.0.1",
		"nistp256,0x40a89256e8c70c29f2aaf258e1c215c9f3cf3bb68853bf12743aee2503482ee9,0x3adb436609cc23eb24a184f7362a1969182ecb75e27910b2657d2cc8403da13d",
	}, {
		"10.10.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbYpA+mytM+DBTasSFv44NuXAWxNbCOSZe3UJ0WO9ZF",
		"ssh-ed25519@22:10.10.0.1",
		"0x32d013e2996f93c5f5cec2ab3aac303434f31775aababf3ea342e1227ab4ac36,0x45d63b169d50b797498eb035b1055c6e83e36f21b1da140c3ed3caa60fa4d866",
	}}

	for i, test := range tests {
		sshKey := test[0]
		puttyKey := test[1]
		puttyValue := test[2]
		t.Run(fmt.Sprintf("%d-%s", i, puttyKey), func(t *testing.T) {
			t.Parallel()
			gotKey, gotValue, err := putty_hosts.ToPutty(sshKey)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if gotKey != puttyKey {
				t.Errorf("expected %q got %q", puttyKey, gotKey)
			}
			if gotValue != puttyValue {
				t.Errorf("expected %q got %q", puttyValue, gotValue)
			}
		})
	}
}
