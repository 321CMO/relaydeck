package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type telegramError struct {
	code  int
	retry int
}

func (e telegramError) Error() string {
	if e.code == 429 {
		return "Telegram 限流，稍后自动重试"
	}
	if e.code == 401 {
		return "Bot Token 无效"
	}
	if e.code == 403 {
		return "Bot 无法向该会话发送通知，请先私聊 Bot"
	}
	return "Telegram 请求失败，请检查网络和接收目标"
}
func (a *App) telegramCall(ctx context.Context, token, method string, values url.Values) (json.RawMessage, error) {
	if token == "" || strings.ContainsAny(token, "/?#\r\n") || !strings.Contains(token, ":") {
		return nil, errors.New("请填写有效的 Bot Token")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", a.TelegramBase+"/bot"+token+"/"+method, strings.NewReader(values.Encode()))
	if e != nil {
		return nil, errors.New("Telegram 请求无效")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, e := a.client.Do(req)
	if e != nil {
		return nil, errors.New("无法连接 Telegram，请检查服务器网络")
	}
	defer res.Body.Close()
	var out struct {
		OK         bool            `json:"ok"`
		Result     json.RawMessage `json:"result"`
		Code       int             `json:"error_code"`
		Parameters struct {
			Retry int `json:"retry_after"`
		} `json:"parameters"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); e != nil {
		return nil, errors.New("Telegram 返回无效响应")
	}
	if !out.OK || res.StatusCode != 200 {
		return nil, telegramError{out.Code, out.Parameters.Retry}
	}
	return out.Result, nil
}
func (a *App) sendTelegram(ctx context.Context, t Telegram, message string) error {
	if t.ChatID == "" {
		return errors.New("请先填写接收目标 Chat ID，并私聊 Bot")
	}
	_, e := a.telegramCall(ctx, t.Token, "sendMessage", url.Values{"chat_id": {t.ChatID}, "text": {message}, "protect_content": {"true"}, "disable_web_page_preview": {"true"}})
	return e
}
func (a *App) verifyTelegram(w http.ResponseWriter, r *http.Request) {
	s := a.Store.Read()
	b, e := a.telegramCall(r.Context(), s.Settings.Telegram.Token, "getMe", url.Values{})
	if e != nil {
		failureResponse(w, 502, e)
		return
	}
	var me struct {
		Username string `json:"username"`
		IsBot    bool   `json:"is_bot"`
	}
	if e = json.Unmarshal(b, &me); e != nil || !me.IsBot {
		failureResponse(w, 502, errors.New("此账号不是 Telegram Bot"))
		return
	}
	_ = a.Store.Update(func(s *State) error { s.Settings.Telegram.Status = "verified"; return nil })
	jsonResponse(w, 200, map[string]string{"bot": me.Username})
}
func enqueueNotification(s *State, kind, message string) {
	if !s.Settings.Telegram.Enabled {
		return
	}
	for _, n := range s.Notifications {
		if n.Kind == kind && (n.Status == "pending" || time.Since(n.Created) < 30*time.Minute) {
			return
		}
	}
	s.Notifications = append(s.Notifications, Notification{ID: newID("tg"), Kind: kind, Text: message, Status: "pending", Created: time.Now().UTC(), Next: time.Now().UTC()})
	if len(s.Notifications) > 500 {
		s.Notifications = s.Notifications[len(s.Notifications)-500:]
	}
}

// RunBackground enforces expiry in desired configs and delivers persisted admin alerts.
func (a *App) RunBackground(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	previous := map[string]bool{}
	daily := ""
	expired := map[string]bool{}
	httpsTick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := time.Now()
			_ = a.Store.Update(func(s *State) error {
				for _, v := range s.Servers {
					online := v.online()
					was, known := previous[v.ID]
					if known && online != was {
						kind := "offline"
						msg := "管理连接离线"
						if online {
							kind = "recovered"
							msg = "管理连接恢复"
						}
						enqueueNotification(s, kind+":"+v.ID, "RelayDeck：服务器「"+v.Name+"」"+msg)
					}
					previous[v.ID] = online
				}
				for _, u := range s.Users {
					inactive := !activeUser(u, now)
					if inactive && !expired[u.ID] {
						ids := []string{}
						for _, nid := range u.NodeIDs {
							if n := nodeByID(s, nid); n != nil {
								ids = append(ids, n.ServerID)
							}
						}
						queue(s, ids, "应用用户停用或到期")
						if u.Enabled {
							enqueueNotification(s, "expiry:"+u.ID, "RelayDeck：朋友「"+u.Name+"」已到期或达到额度")
						}
					}
					expired[u.ID] = inactive
				}
				loc, e := time.LoadLocation(s.Settings.Timezone)
				if e == nil && s.Settings.Telegram.Daily {
					t := now.In(loc)
					day := t.Format("2006-01-02")
					if t.Hour() == s.Settings.Telegram.Hour && daily != day {
						daily = day
						enqueueNotification(s, "daily:"+day, fmt.Sprintf("RelayDeck 每日摘要：%d 台服务器，%d 个节点，%d 位朋友。流量统计尚未接入。", len(s.Servers), len(s.Nodes), len(s.Users)))
					}
				}
				return nil
			})
			httpsTick++
			if httpsTick%4 == 0 {
				a.checkHTTPS(ctx)
			}
			snapshot := a.Store.Read()
			for _, n := range snapshot.Notifications {
				if n.Status != "pending" || now.Before(n.Next) {
					continue
				}
				if !snapshot.Settings.Telegram.Enabled {
					break
				}
				e := a.sendTelegram(ctx, snapshot.Settings.Telegram, n.Text)
				_ = a.Store.Update(func(s *State) error {
					for i := range s.Notifications {
						v := &s.Notifications[i]
						if v.ID != n.ID {
							continue
						}
						v.Attempts++
						if e == nil {
							v.Status = "sent"
						} else if v.Attempts >= 5 {
							v.Status = "failed"
						} else {
							delay := time.Duration(1<<v.Attempts) * time.Minute
							if te, ok := e.(telegramError); ok && te.retry > 0 {
								delay = time.Duration(te.retry) * time.Second
							}
							v.Next = now.Add(delay)
						}
						break
					}
					return nil
				})
				break
			}
		}
	}
}
