// testbridge drives the real HTTP handler over stdio for socket-restricted UI tests.
// It is a test tool and is not included in installation packages.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/321CMO/relaydeck/internal/panel"
	"github.com/321CMO/relaydeck/internal/webassets"
)

func main() {
	dir := flag.String("data", "", "isolated test data directory")
	flag.Parse()
	if *dir == "" {
		panic("test data directory required")
	}
	s, e := panel.OpenStore(*dir)
	if e != nil {
		panic(e)
	}
	defer s.Close()
	app := panel.New(s, "http://127.0.0.1:8787", *dir, true, webassets.Files())
	handler := app.Handler()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 16<<20)
	out := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		var in struct {
			ID      int               `json:"id"`
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		}
		if json.Unmarshal(scan.Bytes(), &in) != nil {
			panic("invalid test request")
		}
		req := httptest.NewRequest(in.Method, in.URL, strings.NewReader(in.Body))
		for k, v := range in.Headers {
			req.Header.Set(k, v)
		}
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		out.Encode(map[string]any{"id": in.ID, "status": w.Code, "headers": w.Header(), "body": base64.StdEncoding.EncodeToString(w.Body.Bytes())})
	}
}
