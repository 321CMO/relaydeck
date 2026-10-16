package panel

import (
	"errors"
	"net/http"
	"slices"
)

func (a *App) routingAPI(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) == 0 || !slices.Contains([]string{"routes", "outbounds", "routing"}, parts[0]) {
		return false
	}
	if a.outboundImportAPI(w, r, parts) {
		return true
	}
	s := a.Store.Read()
	if r.Method == "GET" && r.URL.Path == "/api/routing/preview" {
		server := serverByID(&s, r.URL.Query().Get("server"))
		if server == nil {
			failureResponse(w, 422, errors.New("请选择服务器"))
			return true
		}
		server.Desired = max(server.Desired, 1)
		d, e := Compile(s, server.ID, a.AgentDir)
		if e != nil {
			failureResponse(w, 422, e)
			return true
		}
		v, e := redactedRouting(d.Config)
		if e != nil {
			failureResponse(w, 500, e)
			return true
		}
		jsonResponse(w, 200, v)
		return true
	}
	if r.Method != "POST" && r.Method != "DELETE" {
		failureResponse(w, 405, errors.New("请求方式无效"))
		return true
	}
	var result any = map[string]bool{"ok": true}
	var e error
	switch {
	case len(parts) == 2 && parts[0] == "routes" && parts[1] == "reorder" && r.Method == "POST":
		var input struct {
			Scope    string   `json:"scope"`
			ServerID string   `json:"serverId"`
			IDs      []string `json:"ids"`
		}
		if e = body(r, &input); e == nil {
			e = a.Store.Update(func(s *State) error {
				if input.Scope != "client" && input.Scope != "server" {
					return errors.New("规则位置无效")
				}
				if input.Scope == "server" && serverByID(s, input.ServerID) == nil {
					return errors.New("服务器不存在")
				}
				indices := []int{}
				byID := map[string]Route{}
				for i, v := range s.Routes {
					if v.Scope == input.Scope && (input.Scope == "client" || v.ServerID == input.ServerID || v.ServerID == "") {
						indices = append(indices, i)
						byID[v.ID] = v
					}
				}
				if len(input.IDs) != len(indices) {
					return errors.New("规则列表已变化，请刷新后重排")
				}
				seen := map[string]bool{}
				for _, id := range input.IDs {
					if _, ok := byID[id]; !ok || seen[id] {
						return errors.New("排序必须完整包含当前列表且不能重复")
					}
					seen[id] = true
				}
				for i, index := range indices {
					s.Routes[index] = byID[input.IDs[i]]
				}
				queueRouting(s, input.Scope)
				s.Schema = max(s.Schema, 5)
				return nil
			})
		}
	case len(parts) == 2 && parts[0] == "routing" && parts[1] == "policy" && r.Method == "POST":
		var p RoutingPolicy
		if e = body(r, &p); e == nil {
			e = a.Store.Update(func(s *State) error {
				savePolicy(s, p)
				if e := validateRoutingState(*s); e != nil {
					return e
				}
				s.Schema = max(s.Schema, 5)
				queue(s, []string{p.ServerID}, "更新默认出站与路由设置")
				return nil
			})
		}
	case parts[0] == "outbounds" && len(parts) <= 2:
		id := ""
		if len(parts) == 2 {
			id = parts[1]
		}
		var input Outbound
		if r.Method != "DELETE" {
			e = body(r, &input)
		}
		if e == nil {
			e = a.updateMutation(r, input, &result, func(s *State) error {
				old := outboundByID(s, id)
				if id != "" && old == nil {
					return errors.New("出站不存在")
				}
				if r.Method == "DELETE" {
					if old == nil {
						return errors.New("请选择出站")
					}
					for _, n := range s.Nodes {
						if n.OutboundID == id {
							return errors.New("出站仍被入站节点引用，请先修改节点出口")
						}
					}
					for _, r := range s.Routes {
						if r.OutboundID == id {
							return errors.New("出站仍被路由规则引用，请先修改规则")
						}
					}
					for _, o := range s.Outbounds {
						if o.DetourID == id {
							return errors.New("出站仍被代理链引用，请先修改链式出站")
						}
					}
					for _, p := range s.RoutingPolicies {
						if p.DefaultOutboundID == id {
							return errors.New("出站仍是默认出口，请先修改默认出站")
						}
					}
					server := old.ServerID
					s.Outbounds = slices.DeleteFunc(s.Outbounds, func(o Outbound) bool { return o.ID == id })
					s.Schema = max(s.Schema, 5)
					queue(s, []string{server}, "删除出站")
					return nil
				}
				if old != nil {
					if old.ServerID != input.ServerID {
						return errors.New("出站所属服务器不能修改，请新建出站")
					}
					input.ID = old.ID
					if old.Type == input.Type {
						if input.Password == "" {
							input.Password = old.Password
						}
						if input.UUID == "" {
							input.UUID = old.UUID
						}
					}
				} else {
					input.ID = newID("out")
				}
				if (input.Type == "socks" || input.Type == "http") && input.Username == "" {
					input.Password = ""
				}
				if input.Obfs == "" {
					input.ObfsPassword = ""
				} else if old != nil && old.Type == input.Type && input.Obfs == old.Obfs && input.ObfsPassword == "" {
					input.ObfsPassword = old.ObfsPassword
				}
				input.HasObfsPassword = false
				input.HasPassword = false
				input.HasUUID = false
				if old == nil {
					s.Outbounds = append(s.Outbounds, input)
				} else {
					*old = input
				}
				if e := validateRoutingState(*s); e != nil {
					return e
				}
				s.Schema = max(s.Schema, 5)
				queue(s, []string{input.ServerID}, "更新出站 "+input.Name)
				result = map[string]string{"id": input.ID}
				return nil
			})
		}
	case parts[0] == "routes" && len(parts) <= 2:
		id := ""
		if len(parts) == 2 {
			id = parts[1]
		}
		var input Route
		if r.Method != "DELETE" {
			e = body(r, &input)
		}
		if e == nil {
			e = a.updateMutation(r, input, &result, func(s *State) error {
				index := slices.IndexFunc(s.Routes, func(v Route) bool { return v.ID == id })
				if id != "" && index < 0 {
					return errors.New("规则不存在")
				}
				if r.Method == "DELETE" {
					if index < 0 {
						return errors.New("请选择规则")
					}
					scope := s.Routes[index].Scope
					s.Routes = slices.Delete(s.Routes, index, index+1)
					queueRouting(s, scope)
					s.Schema = max(s.Schema, 5)
					return nil
				}
				if e := validateRoute(*s, input); e != nil {
					return e
				}
				if index >= 0 {
					input.ID = id
					s.Routes[index] = input
				} else {
					input.ID = newID("rule")
					s.Routes = append(s.Routes, input)
				}
				if input.Scope == "server" && routeEnabled(input) && len(input.Protocols) > 0 {
					for _, server := range s.Servers {
						if input.ServerID == "" || server.ID == input.ServerID {
							p := policyFor(*s, server.ID)
							p.Sniff = true
							savePolicy(s, p)
						}
					}
				}
				if e := validateRoutingState(*s); e != nil {
					return e
				}
				s.Schema = max(s.Schema, 5)
				queueRouting(s, input.Scope)
				result = map[string]string{"id": input.ID}
				return nil
			})
		}
	default:
		http.NotFound(w, r)
		return true
	}
	if e != nil {
		failureResponse(w, 422, e)
	} else {
		jsonResponse(w, 200, result)
	}
	return true
}
func queueRouting(s *State, scope string) {
	if scope == "client" {
		return
	}
	ids := []string{}
	for _, server := range s.Servers {
		ids = append(ids, server.ID)
	}
	queue(s, ids, "更新路由规则")
}
