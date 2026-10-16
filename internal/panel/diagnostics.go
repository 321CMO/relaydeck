package panel

import (
	"regexp"
	"strings"
	"time"
)

var diagnosticCredential = regexp.MustCompile(`(?i)(password|token|uuid|private_key|obfs-password)([=:]\s*)[^\s,;"}]+`)

func redactDiagnostic(s State, message string) string {
	secrets := []string{s.PasswordHash, s.SetupToken, s.Settings.Telegram.Token, s.Settings.HTTPS.CloudflareToken, s.Settings.HTTPS.Key}
	for _, v := range s.Servers {
		secrets = append(secrets, v.AgentToken, v.BackhaulKey)
	}
	for _, v := range s.Nodes {
		secrets = append(secrets, v.PrivateKey, v.ServerKey, v.ObfsPassword, v.Key)
	}
	for _, v := range s.Outbounds {
		secrets = append(secrets, v.Password, v.UUID, v.ObfsPassword)
	}
	for _, v := range s.Users {
		secrets = append(secrets, v.Token)
		for _, secret := range v.Credentials {
			secrets = append(secrets, secret)
		}
	}
	for _, secret := range secrets {
		if len(secret) >= 4 {
			message = strings.ReplaceAll(message, secret, "[已隐藏]")
		}
	}
	return diagnosticCredential.ReplaceAllString(message, `${1}${2}[已隐藏]`)
}

func deliveryReadiness(s State, u User) map[string]any {
	items := []map[string]string{}
	ready := 0
	for _, id := range u.NodeIDs {
		n := nodeByID(&s, id)
		name := id
		reason := "节点不存在"
		if n != nil {
			name = n.Name
			switch {
			case !u.Enabled:
				reason = "订阅已停用"
			case !activeUser(u, time.Now()):
				reason = "订阅已到期"
			case !n.Enabled:
				reason = "节点已停用"
			case nodePublished(s, u, *n):
				reason = "已应用，可交付（实际连通需检测）"
				ready++
			default:
				reason = "授权或节点配置尚未应用，请查看服务器任务"
			}
		}
		items = append(items, map[string]string{"id": id, "name": name, "reason": reason})
	}
	return map[string]any{"total": len(u.NodeIDs), "ready": ready, "items": items}
}
