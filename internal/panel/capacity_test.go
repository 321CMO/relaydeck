package panel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// Benchmarks exercise an authenticated control plane; they do not measure
// proxy throughput or establish a production capacity promise.
func BenchmarkCommercialFleet(b *testing.B) {
	for _, kind := range []string{"agent_sync", "subscription_120_nodes", "admin_state", "node_save", "compile_3_nodes_50_users"} {
		b.Run(kind, func(b *testing.B) {
			store, e := OpenStore(b.TempDir())
			if e != nil {
				b.Fatal(e)
			}
			defer store.Close()
			s := initial()
			s.Username = "capacity-admin"
			s.Schema = 7
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hy.example.test"}, DNSNames: []string{"hy.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
			rawKey, _ := x509.MarshalPKCS8PrivateKey(k)
			crt := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey}))
			for i := 0; i < 40; i++ {
				srv := Server{ID: fmt.Sprintf("srv_capacity_%02d", i), Name: fmt.Sprintf("capacity-%02d", i), Address: fmt.Sprintf("server-%02d.example.test", i), PrivateIP: fmt.Sprintf("10.50.%d.1", i), AgentToken: randomToken(32), BackhaulKey: ssKey(), MachineID: fmt.Sprintf("capacity-%d", i), LastSeen: time.Now(), Desired: 3, Applied: 3, StatsSupported: true}
				s.Servers = append(s.Servers, srv)
				for j, p := range []string{"reality", "hy2", "ss2022"} {
					priv, pub, _ := realityKeys()
					n := Node{ID: fmt.Sprintf("node_capacity_%02d_%d", i, j), Name: p, ServerID: srv.ID, Protocol: p, Address: srv.Address, Port: 18443 + j, Enabled: true, SNI: "www.microsoft.com", Target: "www.microsoft.com:443", PrivateKey: priv, PublicKey: pub, ShortID: shortID(), ServerKey: ssKey(), RequiredRevision: 3}
					if p == "hy2" {
						n.SNI = "hy.example.test"
						n.TLSMode = "import"
						n.Certificate = crt
						n.Key = key
					}
					s.Nodes = append(s.Nodes, n)
				}
			}
			for i := 0; i < 50; i++ {
				u := User{ID: fmt.Sprintf("user_capacity_%02d", i), Name: fmt.Sprintf("capacity-%02d", i), Token: randomToken(32), Enabled: true, Credentials: map[string]string{}, Required: map[string]int64{}}
				for _, n := range s.Nodes {
					u.NodeIDs = append(u.NodeIDs, n.ID)
					u.Credentials[n.ID] = credential(n.Protocol)
				}
				s.Users = append(s.Users, u)
			}
			for i := 0; i < auditRetention; i++ {
				s.Audit = append(s.Audit, AuditEvent{ID: newID("audit"), Time: time.Now(), Actor: s.Username, Source: "127.0.0.1", Action: "update", Resource: "nodes", TargetIDs: []string{s.Nodes[0].ID}, Fields: []string{"name"}})
			}
			if e = store.Update(func(v *State) error { *v = s; return nil }); e != nil {
				b.Fatal(e)
			}
			a := New(store, "http://127.0.0.1:8787", store.dir, true, nil)
			authWriter := httptest.NewRecorder()
			sess := a.auth.login(authWriter, "/")
			cookie := authWriter.Result().Cookies()[0]
			handler := a.Handler()
			initialBytes, _ := json.Marshal(s)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if kind == "compile_3_nodes_50_users" {
					if _, e := Compile(s, s.Servers[0].ID, "/var/lib/relaydeck/agent"); e != nil {
						b.Fatal(e)
					}
					continue
				}
				method, path := "GET", "/api/state"
				var body []byte
				token := ""
				switch kind {
				case "agent_sync":
					v := s.Servers[i%len(s.Servers)]
					method = "POST"
					path = "/api/agent/sync"
					token = v.AgentToken
					body, _ = json.Marshal(map[string]any{"serverId": v.ID, "applied": 3, "statsSupported": true, "epoch": "", "coreVersion": "capacity-test"})
				case "subscription_120_nodes":
					path = "/s/" + s.Users[i%50].Token + "?format=clash"
				case "node_save":
					method = "POST"
					path = "/api/nodes/" + s.Nodes[0].ID
					n := s.Nodes[0]
					n.Name = "capacity-" + strconv.Itoa(i)
					body, _ = json.Marshal(n)
				}
				r := httptest.NewRequest(method, path, bytes.NewReader(body))
				r.AddCookie(cookie)
				r.Header.Set("X-CSRF-Token", sess.CSRF)
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != 200 {
					b.Fatal(kind, w.Code, w.Body.String())
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(len(initialBytes)), "state_bytes")
		})
	}
}
