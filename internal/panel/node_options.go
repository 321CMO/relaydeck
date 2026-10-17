package panel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

func ssKeyFor(method string) string {
	b := make([]byte, ssKeySize(method))
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func prepareNodeOptions(s *State, in *Node, old *Node) error {
	clean := []string{}
	for _, id := range in.ShortIDs {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			clean = append(clean, id)
		}
	}
	in.ShortIDs = clean
	in.ShortID = strings.ToLower(strings.TrimSpace(in.ShortID))
	if old != nil {
		if in.PrivateKey == "" {
			in.PrivateKey = old.PrivateKey
		}
		if in.ServerKey == "" && ssMethod(in.ProtocolOptions) == ssMethod(old.ProtocolOptions) {
			in.ServerKey = old.ServerKey
		}
		if in.Obfs == old.Obfs && in.ObfsPassword == "" {
			in.ObfsPassword = old.ObfsPassword
		}
		if in.ShortID == "" && len(in.ShortIDs) == 0 {
			in.ShortID = old.ShortID
			in.ShortIDs = append([]string(nil), old.ShortIDs...)
		}
	}
	if old != nil && in.Protocol == "reality" && old.PrivateKey != "" && in.PrivateKey != old.PrivateKey && !in.RotateCredentials {
		return errors.New("更改 Reality 私钥会使旧客户端无法连接，请确认轮换并通知使用者刷新订阅")
	}
	if in.Obfs == "" {
		in.ObfsPassword = ""
	}
	if in.PrivateKey == "" {
		var e error
		in.PrivateKey, in.PublicKey, e = realityKeys()
		if e != nil {
			return e
		}
	} else {
		b, e := base64.RawURLEncoding.DecodeString(in.PrivateKey)
		if e != nil {
			return errors.New("Reality 私钥应为 X25519 Base64URL 密钥")
		}
		key, e := ecdh.X25519().NewPrivateKey(b)
		if e != nil {
			return errors.New("Reality 私钥无效")
		}
		in.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	if len(in.ShortIDs) > 0 {
		in.ShortID = in.ShortIDs[0]
	} else if in.ShortID == "" {
		in.ShortID = shortID()
	}
	if in.ServerKey == "" {
		in.ServerKey = ssKeyFor(ssMethod(in.ProtocolOptions))
	}
	if old != nil && in.Protocol == "ss2022" && (in.ServerKey != old.ServerKey || ssMethod(in.ProtocolOptions) != ssMethod(old.ProtocolOptions)) {
		if !in.RotateCredentials {
			return errors.New("更改 SS2022 算法或主密钥会更新客户端密钥，请勾选确认轮换")
		}
		for i := range s.Users {
			if _, ok := s.Users[i].Credentials[in.ID]; ok {
				s.Users[i].Credentials[in.ID] = ssKeyFor(ssMethod(in.ProtocolOptions))
			}
		}
	}
	in.HasPrivateKey = false
	in.HasServerKey = false
	in.HasObfsPassword = false
	in.RotateCredentials = false
	return nil
}
func (a *App) protocolAPI(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) == 2 && parts[0] == "nodes" && parts[1] == "generate-keys" && r.Method == "POST" {
		var input struct {
			Type   string `json:"type"`
			Method string `json:"method"`
		}
		if e := body(r, &input); e != nil {
			failureResponse(w, 422, e)
			return true
		}
		if input.Type == "reality" {
			private, public, e := realityKeys()
			if e != nil {
				failureResponse(w, 500, e)
			} else {
				id := shortID()
				jsonResponse(w, 200, map[string]any{"privateKey": private, "publicKey": public, "shortId": id, "shortIds": []string{id}})
			}
		} else if input.Type == "short-id" {
			jsonResponse(w, 200, map[string]string{"shortId": shortID()})
		} else if input.Type == "hy2" {
			jsonResponse(w, 200, map[string]string{"obfsPassword": randomToken(32)})
		} else if input.Type == "ss2022" {
			p := ProtocolOptions{Method: input.Method}
			if e := validateProtocol(p, "ss2022"); e != nil {
				failureResponse(w, 422, e)
			} else {
				jsonResponse(w, 200, map[string]string{"serverKey": ssKeyFor(ssMethod(p))})
			}
		} else {
			failureResponse(w, 422, errors.New("请选择密钥类型"))
		}
		return true
	}
	if len(parts) == 3 && parts[0] == "nodes" && parts[2] == "secrets" && r.Method == "GET" {
		s := a.Store.Read()
		n := nodeByID(&s, parts[1])
		if n == nil {
			failureResponse(w, 404, errors.New("节点不存在"))
		} else {
			jsonResponse(w, 200, map[string]string{"privateKey": n.PrivateKey, "serverKey": n.ServerKey, "obfsPassword": n.ObfsPassword})
		}
		return true
	}
	return false
}
