package panel

import (
	"errors"
	"time"
)

func (a *App) saveSettings(s *State, in Settings) error {
	if in.Timezone == "" {
		in.Timezone = s.Settings.Timezone
	}
	if _, e := time.LoadLocation(in.Timezone); e != nil {
		return errors.New("时区无效")
	}
	if in.RoutingPreset != "china-direct" && in.RoutingPreset != "proxy-all" {
		return errors.New("分流预设无效")
	}
	if in.Telegram.Hour < 0 || in.Telegram.Hour > 23 {
		return errors.New("日报时间无效")
	}
	if in.Telegram.Token == "" {
		in.Telegram.Token = s.Settings.Telegram.Token
	}
	if in.HTTPS.CloudflareToken == "" {
		in.HTTPS.CloudflareToken = s.Settings.HTTPS.CloudflareToken
	}
	if in.HTTPS.Certificate == "" {
		in.HTTPS.Certificate = s.Settings.HTTPS.Certificate
	}
	if in.HTTPS.Key == "" {
		in.HTTPS.Key = s.Settings.HTTPS.Key
	}
	in.HTTPS.AdminPort = s.Settings.HTTPS.AdminPort
	in.HTTPS.AdminPath = s.Settings.HTTPS.AdminPath
	in.HTTPS.LoadedHash = s.Settings.HTTPS.LoadedHash
	in.HTTPS.PublishedDomain = s.Settings.HTTPS.PublishedDomain
	if in.HTTPS.PublishedDomain != "" && in.HTTPS.SubscriptionDomain != in.HTTPS.PublishedDomain {
		return errors.New("此订阅域名已交付给朋友；完整域名迁移尚未开放，请保留原域名")
	}
	if in.HTTPS.Domain != "" {
		if _, e := Caddyfile(in.HTTPS, "127.0.0.1:8787", a.DataDir); e != nil {
			return e
		}
		in.HTTPS.Status = "pending"
	} else {
		in.HTTPS.Status = "unconfigured"
	}
	if in.HTTPS.Mode == "import" {
		cert, e := parseCertificate(in.HTTPS.Certificate, in.HTTPS.Key, in.HTTPS.Domain)
		if e != nil {
			return e
		}
		in.HTTPS.Expires = cert.NotAfter.UTC().Format(time.RFC3339)
	}
	if httpsFingerprint(in.HTTPS) == httpsFingerprint(s.Settings.HTTPS) {
		in.HTTPS.Status = s.Settings.HTTPS.Status
		in.HTTPS.Expires = s.Settings.HTTPS.Expires
	}
	in.Telegram.Status = "unverified"
	if in.Telegram.Token == s.Settings.Telegram.Token && in.Telegram.ChatID == s.Settings.Telegram.ChatID {
		in.Telegram.Status = s.Settings.Telegram.Status
	}
	s.Settings = in
	return nil
}
