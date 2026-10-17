package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
)

func settingsVersion(s Settings, section string) string {
	var value any
	switch section {
	case "https":
		return httpsFingerprint(s.HTTPS)
	case "telegram":
		s.Telegram.Status = ""
		value = struct {
			Telegram Telegram
			Timezone string
		}{s.Telegram, s.Timezone}
	case "routing":
		value = s.RoutingPreset
	default:
		return ""
	}
	b, _ := json.Marshal(value)
	return digest(string(b))
}
func settingsVersions(s Settings) map[string]string {
	return map[string]string{"https": settingsVersion(s, "https"), "telegram": settingsVersion(s, "telegram"), "routing": settingsVersion(s, "routing")}
}

func (a *App) settingsSection(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Section string          `json:"section"`
		Version string          `json:"version"`
		Value   json.RawMessage `json:"value"`
	}
	if err := body(r, &input); err != nil {
		failureResponse(w, 400, err)
		return
	}
	conflict := false
	err := a.Store.Update(func(s *State) error {
		version := settingsVersion(s.Settings, input.Section)
		if version == "" {
			return errors.New("未知设置分区")
		}
		if input.Version == "" || !equal(version, input.Version) {
			conflict = true
			return errors.New("此分区已在其他页面修改。当前输入已保留，请载入最新设置后核对差异")
		}
		next := s.Settings
		var target any
		tg := struct {
			Telegram Telegram `json:"telegram"`
			Timezone string   `json:"timezone"`
		}{next.Telegram, next.Timezone}
		routing := struct {
			Preset string `json:"routingPreset"`
		}{next.RoutingPreset}
		switch input.Section {
		case "https":
			target = &next.HTTPS
		case "telegram":
			target = &tg
		case "routing":
			target = &routing
		}
		decoder := json.NewDecoder(bytes.NewReader(input.Value))
		decoder.DisallowUnknownFields()
		if e := decoder.Decode(target); e != nil {
			return errors.New("分区设置格式无效")
		}
		if input.Section == "telegram" {
			next.Telegram = tg.Telegram
			next.Timezone = tg.Timezone
		}
		if input.Section == "routing" {
			next.RoutingPreset = routing.Preset
		}
		if e := a.saveSettings(s, next); e != nil {
			return e
		}
		a.audit(s, r, "settings.update", "settings", nil, []string{input.Section})
		return nil
	})
	if err != nil {
		status := 422
		if conflict {
			status = 409
		}
		failureResponse(w, status, err)
		return
	}
	jsonResponse(w, 200, map[string]any{"ok": true, "versions": settingsVersions(a.Store.Read().Settings)})
}
