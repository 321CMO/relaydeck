package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Receipts are encrypted with the state and committed atomically with the object.
// They never appear in the public state (registration responses contain secrets).
type MutationReceipt struct {
	Key      string          `json:"key"`
	Input    string          `json:"input"`
	Response json.RawMessage `json:"response"`
	Expires  time.Time       `json:"expires"`
}

func (a *App) updateMutation(r *http.Request, input any, response *any, fn func(*State) error) error {
	key := r.Header.Get("Idempotency-Key")
	if key == "" || r.Method != "POST" {
		return a.Store.Update(fn)
	}
	if len(key) < 16 || len(key) > 128 || strings.ContainsAny(key, " \t\r\n") {
		return errors.New("操作标识无效，请重新打开表单")
	}
	b, err := json.Marshal(input)
	if err != nil {
		return err
	}
	key, fingerprint := digest(r.URL.Path+"\x00"+key), digest(string(b))
	return a.Store.Update(func(s *State) error {
		now := time.Now().UTC()
		for _, receipt := range s.Mutations {
			if receipt.Key == key && now.Before(receipt.Expires) {
				if receipt.Input != fingerprint {
					return errors.New("同一操作的内容已变化，请重新核对并提交")
				}
				return json.Unmarshal(receipt.Response, response)
			}
		}
		if err := fn(s); err != nil {
			return err
		}
		body, err := json.Marshal(*response)
		if err != nil {
			return err
		}
		kept := []MutationReceipt{}
		for _, receipt := range s.Mutations {
			if now.Before(receipt.Expires) {
				kept = append(kept, receipt)
			}
		}
		if len(kept) >= 256 {
			kept = kept[len(kept)-255:]
		}
		s.Mutations = append(kept, MutationReceipt{Key: key, Input: fingerprint, Response: body, Expires: now.Add(24 * time.Hour)})
		s.Schema = max(s.Schema, 6)
		return nil
	})
}
