package panel

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

//go:embed portal.html
var portalHTML string
var portalTemplate = template.Must(template.New("portal").Parse(portalHTML))

func bytesText(v int64) string {
	if v < 1024 {
		return fmt.Sprintf("%d B", v)
	}
	x := float64(v)
	unit := "B"
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB", "PiB"} {
		x /= 1024
		unit = u
		if x < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.2f %s", x, unit)
}
func userForToken(s State, token string) *User {
	if len(token) < 24 {
		return nil
	}
	for i := range s.Users {
		if equal(s.Users[i].Token, token) {
			return &s.Users[i]
		}
	}
	return nil
}
func (a *App) delivery(w http.ResponseWriter, r *http.Request) {
	s := a.Store.Read()
	u := userForToken(s, r.PathValue("token"))
	if u == nil {
		http.NotFound(w, r)
		return
	}
	available := activeUser(*u, time.Now())
	status := "可使用"
	tone := "good"
	if !u.Enabled {
		status = "已停用"
		tone = "warn"
	} else if u.Expires != "" {
		expiry, e := time.Parse(time.RFC3339, u.Expires)
		if e != nil || !time.Now().Before(expiry) {
			status = "已到期"
			tone = "warn"
		}
	}
	if u.Limit > 0 && u.Used >= u.Limit {
		status = "流量已用尽"
		tone = "warn"
	}
	zone, e := time.LoadLocation(s.Settings.Timezone)
	if e != nil {
		zone = time.UTC
	}
	expires := "长期有效"
	if t, e := time.Parse(time.RFC3339, u.Expires); e == nil {
		expires = t.In(zone).Format("2006-01-02 15:04 MST")
	}
	type nodeView struct{ Name, Protocol, Status string }
	nodes := []nodeView{}
	ready := 0
	missing := false
	stale := false
	seen := map[string]bool{}
	for _, id := range u.NodeIDs {
		n := nodeByID(&s, id)
		if n == nil {
			continue
		}
		v := serverByID(&s, n.ServerID)
		ns := "等待配置"
		if !n.Enabled {
			ns = "节点已停用"
		} else if !available {
			ns = "订阅不可使用"
		} else if nodePublished(s, *u, *n) {
			ns = "配置已应用"
			ready++
		}
		if v != nil && available && !v.online() {
			ns = "服务器心跳中断"
		}
		nodes = append(nodes, nodeView{n.Name, map[string]string{"reality": "VLESS Reality", "hy2": "Hysteria 2", "ss2022": "SS2022"}[n.Protocol], ns})
		if seen[n.ServerID] {
			continue
		}
		seen[n.ServerID] = true
		found := false
		if v != nil {
			for _, cursor := range v.TrafficCursors {
				if _, ok := cursor[u.ID]; ok {
					found = true
					break
				}
			}
			if found && time.Since(v.TrafficLastSeen) > 90*time.Second {
				stale = true
			}
		}
		if !found {
			missing = true
		}
	}
	known := !u.UsageUpdated.IsZero()
	used, up, down := "暂无数据", "暂无数据", "暂无数据"
	note := "等待服务器首次上报，尚未产生的统计不会记为零。"
	if known {
		used = bytesText(u.Used)
		up = bytesText(u.Upload)
		down = bytesText(u.Download)
		note = "最后上报：" + u.UsageUpdated.In(zone).Format("2006-01-02 15:04:05 MST")
		if missing {
			note += " · 部分服务器尚未上报，当前为已采集用量"
		} else if stale || time.Since(u.UsageUpdated) > 90*time.Second {
			note += " · 数据暂未更新"
		}
	}
	since := ""
	if !u.UsageSince.IsZero() {
		since = u.UsageSince.In(zone).Format("2006-01-02 15:04 MST")
	}
	limit := "不限量"
	remaining := "不限量"
	if u.Limit > 0 {
		limit = bytesText(u.Limit)
		remaining = bytesText(max(u.Limit-u.Used, 0))
		if !known {
			remaining = "暂无数据"
		}
	}
	base := a.subscriptionBase(s) + "/s/" + u.Token
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	_ = portalTemplate.Execute(w, map[string]any{"Name": u.Name, "Status": status, "Tone": tone, "Expires": expires, "Used": used, "Upload": up, "Download": down, "Limit": limit, "Remaining": remaining, "Note": note, "Since": since, "Ready": ready, "Nodes": nodes, "URL": base, "Clash": base + "?format=clash", "Shadow": base + "?format=shadowrocket", "CanImport": available && ready > 0, "Script": "/delivery/" + u.Token + "/portal.js"})
}
func portalScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(`document.getElementById('copy').addEventListener('click',async()=>{const input=document.getElementById('subscription');const status=document.getElementById('copy-status');try{await navigator.clipboard.writeText(input.value);status.textContent='已复制，粘贴到客户端的订阅地址中即可。'}catch{input.select();status.textContent='请选中并手动复制订阅地址。'}});`))
}

func clientUsageHeader(u User) string {
	if u.UsageUpdated.IsZero() {
		return ""
	}
	value := fmt.Sprintf("upload=%d; download=%d; total=%d", u.Upload, u.Download, u.Limit)
	if expiry, e := time.Parse(time.RFC3339, u.Expires); e == nil {
		value += fmt.Sprintf("; expire=%d", expiry.Unix())
	}
	return strings.TrimSpace(value)
}
