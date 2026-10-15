package panel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

func decodeShareBase64(v string) ([]byte, error) {
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(v); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("Base64 内容无效")
}
func queryValue(q url.Values, keys ...string) (string, error) {
	v := ""
	set := false
	for _, k := range keys {
		for _, value := range q[k] {
			if set && v != value {
				return "", fmt.Errorf("参数 %s 存在冲突值", keys[0])
			}
			v = value
			set = true
		}
	}
	return v, nil
}
func shareBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, errors.New("布尔参数应为 true/false 或 1/0")
}
func shareNumber(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, e := strconv.Atoi(v)
	if e != nil {
		return 0, errors.New("数值参数无效")
	}
	return n, nil
}
func parseOutboundShare(raw string) (Outbound, error) {
	o := Outbound{Enabled: true, HopInterval: 30}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Scheme == "" {
		return o, errors.New("分享链接格式无效")
	}
	// Legacy whole-authority Shadowsocks Base64, including IPv6 and fragments.
	if u.Scheme == "ss" && u.User == nil {
		v := strings.TrimPrefix(raw, "ss://")
		authority, fragment, _ := strings.Cut(v, "#")
		authority, query, _ := strings.Cut(authority, "?")
		b, e := decodeShareBase64(authority)
		if e != nil {
			return o, errors.New("SS 链接认证编码无效")
		}
		at := strings.LastIndexByte(string(b), '@')
		auth, host, ok := "", "", at >= 0
		if ok {
			auth = string(b[:at])
			host = string(b[at+1:])
		}
		method, password, valid := strings.Cut(auth, ":")
		if !ok || !valid {
			return o, errors.New("SS 链接缺少认证或服务器")
		}
		u, e = url.Parse("ss://" + url.UserPassword(method, password).String() + "@" + host + "?" + query + "#" + fragment)
		if e != nil {
			return o, errors.New("SS 链接格式无效")
		}
	}
	u.Scheme = strings.ToLower(u.Scheme)
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return o, errors.New("链接查询参数编码无效")
	}
	allowed := []string{}
	allow := func(keys ...string) { allowed = append(allowed, keys...) }
	get := func(keys ...string) string {
		v, err := queryValue(q, keys...)
		if e == nil && err != nil {
			e = err
		}
		return v
	}
	boolean := func(keys ...string) bool {
		v := get(keys...)
		b, err := shareBool(v)
		if e == nil && err != nil {
			e = err
		}
		return b
	}
	number := func(keys ...string) int {
		v := get(keys...)
		n, err := shareNumber(v)
		if e == nil && err != nil {
			e = err
		}
		return n
	}
	o.Address = u.Hostname()
	if u.Port() != "" {
		o.Port = numberPort(u.Port())
		if o.Port < 1 || o.Port > 65535 {
			return o, errors.New("服务器端口无效")
		}
	}
	if o.Address == "" {
		return o, errors.New("分享链接缺少服务器地址")
	}
	if u.Fragment != "" {
		o.Name = strings.TrimSpace(u.Fragment)
	}
	user := ""
	password := ""
	hasPassword := false
	if u.User != nil {
		user = u.User.Username()
		password, hasPassword = u.User.Password()
	}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		o.Type = "reality"
		o.UUID = user
		if o.Port == 0 {
			o.Port = 443
		}
		allow("security", "type", "encryption", "flow", "sni", "serverName", "fp", "pbk", "sid", "alpn", "headerType", "allowInsecure", "insecure")
		if get("security") != "reality" {
			return o, errors.New("当前 VLESS 导入支持 Reality 安全模式")
		}
		transport := get("type")
		if transport != "" && transport != "tcp" && transport != "raw" {
			return o, errors.New("当前 Reality 导入支持 TCP/RAW；该传输尚未适配")
		}
		if v := get("encryption"); v != "" && v != "none" {
			return o, errors.New("该 VLESS encryption 尚不支持")
		}
		if v := get("headerType"); v != "" && v != "none" {
			return o, errors.New("TCP 伪装参数尚不支持")
		}
		flow := get("flow")
		o.Flow = &flow
		o.SNI = get("sni", "serverName")
		if o.SNI == "" {
			o.SNI = o.Address
		}
		o.Fingerprint = get("fp")
		o.PublicKey = get("pbk")
		o.ShortID = get("sid")
		o.Insecure = boolean("allowInsecure", "insecure")
	case "hy2", "hysteria2":
		o.Type = "hy2"
		if o.Port == 0 {
			o.Port = 443
		}
		allow("sni", "peer", "insecure", "allowInsecure", "alpn", "obfs", "obfs-password", "obfsPassword", "mport", "ports", "hop-interval", "hopInterval", "upmbps", "downmbps", "auth")
		o.Password = user
		if hasPassword {
			o.Password = user + ":" + password
		}
		if o.Password == "" {
			o.Password = get("auth")
		} else if q.Has("auth") && get("auth") != o.Password {
			return o, errors.New("HY2 认证参数存在冲突")
		}
		o.SNI = get("sni", "peer")
		o.Insecure = boolean("insecure", "allowInsecure")
		o.Obfs = get("obfs")
		o.ObfsPassword = get("obfs-password", "obfsPassword")
		o.HopPorts = strings.ReplaceAll(get("mport", "ports"), ":", "-")
		interval := get("hop-interval", "hopInterval")
		if interval != "" {
			o.HopInterval = numberPort(strings.TrimSuffix(interval, "s"))
			if o.HopInterval == 0 {
				return o, errors.New("跳跃间隔使用整数秒，例如 5 或 5s")
			}
		}
		o.UpMbps = number("upmbps")
		o.DownMbps = number("downmbps")
	case "ss":
		o.Type = "ss2022"
		allow("network")
		if !hasPassword {
			b, err := decodeShareBase64(user)
			if err != nil {
				return o, errors.New("SS 链接认证编码无效")
			}
			method, pw, ok := strings.Cut(string(b), ":")
			if !ok {
				return o, errors.New("SS 链接缺少加密方式或密钥")
			}
			user = method
			password = pw
		}
		o.Method = user
		o.Password = password
		o.Network = get("network")
	case "socks", "socks5", "http", "https":
		o.Type = "socks"
		o.Port = defaultPort(o.Port, 1080)
		if u.Scheme == "http" || u.Scheme == "https" {
			o.Type = "http"
			o.TLS = u.Scheme == "https"
			o.Port = defaultPort(numberPort(u.Port()), 80)
			if o.TLS {
				o.Port = defaultPort(numberPort(u.Port()), 443)
			}
		}
		o.Username = user
		o.Password = password
		if o.TLS {
			allow("sni", "insecure", "allowInsecure", "alpn")
		}
		o.SNI = get("sni")
		o.Insecure = boolean("insecure", "allowInsecure")
	default:
		return o, errors.New("当前支持 vless Reality、hy2/hysteria2、SS2022、SOCKS5、HTTP/HTTPS 分享链接")
	}
	if u.Path != "" && u.Path != "/" {
		return o, errors.New("此协议链接不支持自定义路径")
	}
	if o.Type == "hy2" || o.Type == "reality" || o.Type == "http" && o.TLS {
		if v := get("alpn"); v != "" {
			o.ALPN = strings.Split(v, ",")
		}
	}
	for k := range q {
		if !slices.Contains(allowed, k) {
			return o, fmt.Errorf("暂不支持参数 %s，未导入该项", k)
		}
	}
	if e != nil {
		return o, e
	}
	if o.Port < 1 || o.Port > 65535 {
		return o, errors.New("服务器端口无效")
	}
	if o.Name == "" {
		o.Name = net.JoinHostPort(o.Address, strconv.Itoa(o.Port))
	}
	o.Tag = "import-" + digest(o.Type + "|" + o.Address + "|" + strconv.Itoa(o.Port) + "|" + o.Name)[:16]
	return o, nil
}
func defaultPort(port, fallback int) int {
	if port == 0 {
		return fallback
	}
	return port
}
func numberPort(v string) int { n, _ := strconv.Atoi(v); return n }

type importItem struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Summary     string `json:"summary"`
	Error       string `json:"error,omitempty"`
	DuplicateID string `json:"duplicateId,omitempty"`
	DuplicateOf int    `json:"duplicateOf,omitempty"`
}
type parsedImport struct {
	item     importItem
	outbound Outbound
}

func importSnapshot(s State, server string) string {
	out := []Outbound{}
	for _, o := range s.Outbounds {
		if o.ServerID == server {
			out = append(out, o)
		}
	}
	b, _ := json.Marshal(out)
	return digest(string(b))
}
func connectionIdentity(s State, o Outbound) string {
	o.ID = ""
	o.Name = "identity"
	o.Tag = "identity"
	o.ServerID = ""
	o.Enabled = true
	o.DetourID = ""
	o.HasPassword = false
	o.HasUUID = false
	o.HasObfsPassword = false
	// Compare effective native fields so legacy defaults are equivalent to imported defaults.
	o.ID = "identity"
	o.ServerID = "identity-server"
	c := State{Servers: []Server{{ID: o.ServerID}}, Outbounds: []Outbound{o}}
	m, e := compileOutbound(c, o)
	if e != nil {
		return ""
	}
	b, _ := json.Marshal(m)
	return digest(string(b))
}
func duplicateOutbound(s State, o Outbound) *Outbound {
	identity := connectionIdentity(s, o)
	for i, v := range s.Outbounds {
		if v.ServerID == o.ServerID && (v.Tag == o.Tag || identity != "" && connectionIdentity(s, v) == identity) {
			return &s.Outbounds[i]
		}
	}
	return nil
}
func parseOutboundBatch(s State, server, text string) ([]parsedImport, error) {
	if serverByID(&s, server) == nil {
		return nil, errors.New("请选择目标服务器")
	}
	text = strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if len(text) == 0 || len(text) > 512*1024 {
		return nil, errors.New("请粘贴分享链接，内容最多 512 KiB")
	}
	if !strings.Contains(text, "://") {
		b, e := decodeShareBase64(strings.Join(strings.Fields(text), ""))
		if e != nil {
			return nil, errors.New("当前入口接受分享链接、多行链接或 Base64 URI 集合")
		}
		text = string(b)
	}
	rows := []parsedImport{}
	seen := map[string]int{}
	for line, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if len(rows) >= 200 {
			return nil, errors.New("一次最多导入 200 个出站")
		}
		o, e := parseOutboundShare(raw)
		o.ServerID = server
		o.ID = "import-preview"
		r := parsedImport{item: importItem{Index: line + 1, Name: o.Name, Type: o.Type, Address: o.Address, Port: o.Port}, outbound: o}
		if e == nil {
			candidate := cloneState(s)
			candidate.Outbounds = nil
			e = validateOutbound(candidate, o)
		}
		if e != nil {
			r.item.Error = e.Error()
		} else {
			r.item.Summary = "TCP/UDP"
			if o.Type == "http" {
				r.item.Summary = "仅 TCP"
			}
			if o.Type == "reality" {
				r.item.Summary = "TCP/RAW · " + protocolFlow(o.ProtocolOptions) + " · " + fingerprint(o.ProtocolOptions)
			}
			if o.Type == "ss2022" {
				r.item.Summary = ssMethod(o.ProtocolOptions)
			}
			if o.Obfs != "" {
				r.item.Summary += " · " + o.Obfs
			}
			if o.HopPorts != "" {
				r.item.Summary += " · 跳跃 " + o.HopPorts
			}
			if duplicate := duplicateOutbound(s, o); duplicate != nil {
				r.item.DuplicateID = duplicate.ID
			}
			identity := connectionIdentity(s, o)
			if first, ok := seen[identity]; ok && identity != "" {
				r.item.DuplicateOf = first
			} else {
				seen[identity] = line + 1
			}
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, errors.New("内容中没有分享链接")
	}
	return rows, nil
}

func (a *App) outboundImportAPI(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) == 2 && parts[0] == "outbounds" && parts[1] == "export" && r.Method == "GET" {
		s := a.Store.Read()
		sid := r.URL.Query().Get("server")
		if serverByID(&s, sid) == nil {
			failureResponse(w, 422, errors.New("请选择服务器"))
			return true
		}
		links := []string{}
		warnings := []string{}
		for _, o := range s.Outbounds {
			if o.ServerID == sid {
				links = append(links, outboundShare(o))
				for _, warning := range shareWarnings(o) {
					warnings = append(warnings, o.Name+"："+warning)
				}
			}
		}
		jsonResponse(w, 200, map[string]any{"text": strings.Join(links, "\n"), "count": len(links), "warnings": warnings})
		return true
	}

	if len(parts) == 3 && parts[0] == "outbounds" && parts[2] == "share" && r.Method == "GET" {
		s := a.Store.Read()
		o := outboundByID(&s, parts[1])
		if o == nil {
			failureResponse(w, 404, errors.New("出站不存在"))
		} else {
			jsonResponse(w, 200, map[string]any{"link": outboundShare(*o), "warnings": shareWarnings(*o)})
		}
		return true
	}
	if len(parts) != 2 || parts[0] != "outbounds" || parts[1] != "import" || r.Method != "POST" {
		return false
	}
	var input struct {
		ServerID string `json:"serverId"`
		Text     string `json:"text"`
		Preview  bool   `json:"preview"`
		Indices  []int  `json:"indices"`
		Mode     string `json:"mode"`
		Snapshot string `json:"snapshot"`
	}
	if e := body(r, &input); e != nil {
		failureResponse(w, 422, e)
		return true
	}
	s := a.Store.Read()
	rows, e := parseOutboundBatch(s, input.ServerID, input.Text)
	if e != nil {
		failureResponse(w, 422, e)
		return true
	}
	if input.Preview {
		items := []importItem{}
		for _, r := range rows {
			items = append(items, r.item)
		}
		jsonResponse(w, 200, map[string]any{"items": items, "snapshot": importSnapshot(s, input.ServerID)})
		return true
	}
	added, updated, skipped := 0, 0, 0
	e = a.Store.Update(func(s *State) error {
		if input.Snapshot == "" || input.Snapshot != importSnapshot(*s, input.ServerID) {
			return errors.New("出站列表已变化，请重新解析后导入")
		}
		if !slices.Contains([]string{"skip", "new", "replace"}, input.Mode) || len(input.Indices) == 0 || len(input.Indices) > len(rows) {
			return errors.New("请选择有效记录和重复项处理方式")
		}
		selected := map[int]bool{}
		for _, i := range input.Indices {
			if selected[i] {
				return errors.New("导入行不能重复选择")
			}
			selected[i] = true
		}
		for _, r := range rows {
			if !selected[r.item.Index] {
				continue
			}
			delete(selected, r.item.Index)
			if r.item.Error != "" {
				return fmt.Errorf("第 %d 行无法导入：%s", r.item.Index, r.item.Error)
			}
			o := r.outbound
			duplicate := duplicateOutbound(*s, o)
			if duplicate != nil && input.Mode == "skip" {
				skipped++
				continue
			}
			if duplicate != nil && input.Mode == "replace" {
				o.ID = duplicate.ID
				o.Tag = duplicate.Tag
				o.Enabled = duplicate.Enabled
				o.DetourID = duplicate.DetourID
				*duplicate = o
				updated++
			} else {
				o.ID = newID("out")
				base := o.Tag
				for suffix := 2; ; suffix++ {
					conflict := false
					for _, v := range s.Outbounds {
						if v.ServerID == o.ServerID && v.Tag == o.Tag {
							conflict = true
							break
						}
					}
					if !conflict {
						break
					}
					o.Tag = base + "-" + strconv.Itoa(suffix)
				}
				s.Outbounds = append(s.Outbounds, o)
				added++
			}
		}
		if len(selected) > 0 {
			return errors.New("选择的行不存在")
		}
		if e := validateRoutingState(*s); e != nil {
			return e
		}
		if added+updated > 0 {
			s.Schema = 5
			queue(s, []string{input.ServerID}, "导入出站")
		}
		return nil
	})
	if e != nil {
		failureResponse(w, 422, e)
	} else {
		jsonResponse(w, 200, map[string]int{"added": added, "updated": updated, "skipped": skipped})
	}
	return true
}

func outboundShare(o Outbound) string {
	u := url.URL{Host: net.JoinHostPort(o.Address, strconv.Itoa(o.Port)), Fragment: o.Name}
	q := url.Values{}
	switch o.Type {
	case "reality":
		u.Scheme = "vless"
		u.User = url.User(o.UUID)
		q.Set("security", "reality")
		q.Set("type", "tcp")
		q.Set("encryption", "none")
		q.Set("flow", protocolFlow(o.ProtocolOptions))
		q.Set("fp", fingerprint(o.ProtocolOptions))
		q.Set("pbk", o.PublicKey)
		q.Set("sid", o.ShortID)
		q.Set("sni", o.SNI)
	case "hy2":
		u.Scheme = "hysteria2"
		u.User = url.User(o.Password)
		u.Path = "/"
		if o.SNI != "" {
			q.Set("sni", o.SNI)
		}
		if o.Obfs != "" {
			q.Set("obfs", o.Obfs)
			q.Set("obfs-password", o.ObfsPassword)
		}
		if o.UpMbps > 0 {
			q.Set("upmbps", strconv.Itoa(o.UpMbps))
		}
		if o.DownMbps > 0 {
			q.Set("downmbps", strconv.Itoa(o.DownMbps))
		}
		if o.HopPorts != "" {
			q.Set("mport", o.HopPorts)
		} else if o.HopStart > 0 {
			q.Set("mport", fmt.Sprintf("%d-%d", o.HopStart, o.HopEnd))
		}
		if q.Has("mport") {
			q.Set("hop-interval", strconv.Itoa(o.HopInterval))
		}
	case "ss2022":
		u.Scheme = "ss"
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(ssMethod(o.ProtocolOptions) + ":" + o.Password)))
		if o.Network != "" {
			q.Set("network", o.Network)
		}
	case "socks":
		u.Scheme = "socks5"
		if o.Username != "" {
			u.User = url.UserPassword(o.Username, o.Password)
		}
	case "http":
		u.Scheme = "http"
		if o.TLS {
			u.Scheme = "https"
		}
		if o.Username != "" {
			u.User = url.UserPassword(o.Username, o.Password)
		}
		if o.SNI != "" {
			q.Set("sni", o.SNI)
		}
	}
	if o.Insecure {
		q.Set("insecure", "1")
	}
	if len(o.ALPN) > 0 {
		q.Set("alpn", strings.Join(o.ALPN, ","))
	}
	u.RawQuery = q.Encode()
	return u.String()
}
func shareWarnings(o Outbound) []string {
	v := []string{}
	if o.DetourID != "" {
		v = append(v, "分享链接不包含前置代理链；需要在目标端重新指定")
	}
	if o.Type == "ss2022" && o.Network != "" {
		v = append(v, "network 是导入扩展参数，其他客户端可能不识别")
	}
	return v
}
