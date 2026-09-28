package engine_test

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"bannerfp/internal/engine"
	"bannerfp/internal/model"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestFingerprintExamples(t *testing.T) {
	eng, err := engine.LoadDir(filepath.Join("..", "..", "rules"), testLogger())
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	cases := []struct {
		name     string
		item     model.Item
		protocol string
		product  string
		version  string
		osHint   string
	}{
		{"ssh ubuntu", model.Item{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu"},
		{"nginx", model.Item{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", ""},
		{"apache", model.Item{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", ""},
		{"mysql 8", model.Item{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", ""},
		{"redis err", model.Item{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", ""},
		{"proftpd", model.Item{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", ""},
		{"jetty", model.Item{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", ""},
		{"ssh debian", model.Item{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"}, "SSH", "OpenSSH", "9.3", "Debian"},
		{"nginx ubuntu", model.Item{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, "HTTP", "nginx", "1.18.0", "Ubuntu"},
		{"apache ubuntu", model.Item{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, "HTTP", "Apache", "2.4.41", "Ubuntu"},
		{"mysql 5.7", model.Item{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"}, "MySQL", "MySQL", "5.7.42", ""},
		{"redis pong", model.Item{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"}, "Redis", "Redis", "", ""},
		{"vsftpd", model.Item{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, "FTP", "vsFTPd", "3.0.5", ""},
		{"nginx 8443", model.Item{IP: "1.2.3.17", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, "HTTP", "nginx", "1.25.3", ""},
		{"ssh 1.99", model.Item{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", ""},
		{"tls", model.Item{IP: "1.2.3.19", Port: 9999, Banner: "\u0016\u0003\u0001\u00a5\u0001\u0000\u0000\u00a1"}, "TLS", "", "", ""},
		{"iis", model.Item{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "HTTP", "Microsoft-IIS", "10.0", ""},
		{"redis noauth", model.Item{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."}, "Redis", "Redis", "", ""},
		{"pureftpd", model.Item{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", ""},
		{"unknown", model.Item{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"}, "unknown", "", "", ""},
		{"dropbear fallback", model.Item{IP: "1.2.3.30", Port: 2222, Banner: "SSH-2.0-dropbear_2022.83"}, "SSH", "Dropbear", "2022.83", ""},
		{"http protocol fallback", model.Item{IP: "1.2.3.31", Port: 8080, Banner: "HTTP/1.1 200 OK\r\nContent-Length: 0"}, "HTTP", "", "", ""},
		{"ftp protocol fallback", model.Item{IP: "1.2.3.32", Port: 2121, Banner: "220 Service ready"}, "FTP", "", "", ""},
		{"mariadb", model.Item{IP: "1.2.3.33", Port: 3306, Banner: "J\x00\x00\x00\n5.5.5-10.11.2-MariaDB-1:10.11.2+maria~ubu2204\x00"}, "MySQL", "MariaDB", "10.11.2", ""},
		{"openssh windows", model.Item{IP: "1.2.3.34", Port: 22, Banner: "SSH-2.0-OpenSSH_for_Windows_8.1"}, "SSH", "OpenSSH", "8.1", "Windows"},
		{"mysql bare version", model.Item{IP: "1.2.3.35", Port: 3306, Banner: "8.0.36\x00"}, "MySQL", "MySQL", "8.0.36", ""},
		{"regression nginx not redis", model.Item{IP: "1.1.1.1", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/plain\r\n\r\nredis_version:7.4.0"}, "HTTP", "nginx", "", ""},
		{"smtp postfix", model.Item{IP: "1.1.1.2", Port: 25, Banner: "220 mail.example.com ESMTP Postfix"}, "SMTP", "Postfix", "", ""},
		{"smtp exim", model.Item{IP: "1.1.1.3", Port: 587, Banner: "220 mail.example.com ESMTP Exim 4.96"}, "SMTP", "Exim", "4.96", ""},
		{"smtp sendmail", model.Item{IP: "1.1.1.4", Port: 25, Banner: "220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2"}, "SMTP", "Sendmail", "8.15.2", ""},
		{"smtp generic", model.Item{IP: "1.1.1.9", Port: 587, Banner: "220 mail.example.com ESMTP"}, "SMTP", "", "", ""},
		{"binary mysql false positive", model.Item{IP: "1.1.1.5", Port: 443, Banner: "\u0000\u00009.9.9\u0000"}, "unknown", "", "", ""},
		{"bare version false positive", model.Item{IP: "1.1.1.6", Port: 9000, Banner: "1.2.3"}, "unknown", "", "", ""},
		{"redis err wrong port", model.Item{IP: "1.1.1.7", Port: 80, Banner: "-ERR wrong number of arguments for 'get' command"}, "unknown", "", "", ""},
		{"resp array wrong port", model.Item{IP: "1.1.1.8", Port: 8080, Banner: "*12 items"}, "unknown", "", "", ""},
		{"redis info anchored", model.Item{IP: "1.1.1.10", Port: 6379, Banner: "# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n"}, "Redis", "Redis", "7.0.11", ""},
		{"redis info bare line on redis port", model.Item{IP: "1.1.1.11", Port: 6379, Banner: "redis_version:6.2.14\r\n"}, "Redis", "Redis", "6.2.14", ""},
		{"ftp product on nonstandard port", model.Item{IP: "1.1.1.12", Port: 9999, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", ""},
		{"mysql structured version on nonstandard port", model.Item{IP: "1.1.1.13", Port: 13306, Banner: "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Fingerprint(tc.item)
			if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version || got.OSHint != tc.osHint {
				t.Fatalf("got protocol=%q product=%q version=%q os=%q; want protocol=%q product=%q version=%q os=%q",
					got.Protocol, got.Product, got.Version, got.OSHint, tc.protocol, tc.product, tc.version, tc.osHint)
			}
			if tc.protocol == "unknown" && got.Confidence != 0 {
				t.Fatalf("unknown confidence = %v, want 0", got.Confidence)
			}
			if tc.protocol != "unknown" && (got.Confidence <= 0 || got.Confidence > 1) {
				t.Fatalf("confidence = %v, want (0,1]", got.Confidence)
			}
		})
	}
}
