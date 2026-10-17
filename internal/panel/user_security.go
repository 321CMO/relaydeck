package panel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"
)

type userRotationInput struct {
	RotateToken bool     `json:"rotateToken"`
	NodeIDs     []string `json:"nodeIds"`
	Version     string   `json:"version,omitempty"`
	Confirm     bool     `json:"confirm,omitempty"`
}
type rotationConflict struct{}

func (rotationConflict) Error() string {
	return "订阅授权、认证或节点参数已变化，请重新预览后确认；本次没有轮换"
}
func (a *App) rotationPlan(s State, id string, in userRotationInput) (map[string]any, string, error) {
	u := userByID(&s, id)
	if u == nil {
		return nil, "", errors.New("订阅不存在")
	}
	if !in.RotateToken && len(in.NodeIDs) == 0 {
		return nil, "", errors.New("请选择重置订阅地址或需要轮换认证的节点")
	}
	ids := append([]string(nil), in.NodeIDs...)
	slices.Sort(ids)
	items := []map[string]string{}
	servers := []string{}
	metadata := []Node{}
	for i, nid := range ids {
		if i > 0 && ids[i-1] == nid {
			return nil, "", errors.New("节点选择不能重复")
		}
		n := nodeByID(&s, nid)
		if n == nil || !slices.Contains(u.NodeIDs, nid) {
			return nil, "", errors.New("只能轮换此订阅当前已授权的节点")
		}
		items = append(items, map[string]string{"id": nid, "name": n.Name, "protocol": n.Protocol, "serverId": n.ServerID})
		metadata = append(metadata, *n)
		if !slices.Contains(servers, n.ServerID) {
			servers = append(servers, n.ServerID)
		}
	}
	// A keyed version cannot be used to guess saved authentication values.
	copy := *u
	copy.Used = 0
	copy.Upload = 0
	copy.Download = 0
	copy.UsageSince = time.Time{}
	copy.UsageUpdated = time.Time{}
	copy.Required = nil
	b, _ := json.Marshal(struct {
		User        User
		RotateToken bool
		IDs         []string
		Nodes       []Node
	}{copy, in.RotateToken, ids, metadata})
	mac := hmac.New(sha256.New, a.Store.key)
	_, _ = mac.Write(b)
	version := hex.EncodeToString(mac.Sum(nil))
	plan := map[string]any{"userId": id, "name": u.Name, "rotateToken": in.RotateToken, "nodes": items, "serverIds": servers, "version": version}
	return plan, version, nil
}
func (a *App) userSecurityAPI(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) < 3 || parts[0] != "users" || parts[2] != "security" {
		return false
	}
	if len(parts) != 4 || r.Method != "POST" || (parts[3] != "preview" && parts[3] != "rotate") {
		failureResponse(w, 405, errors.New("请求方式无效"))
		return true
	}
	var in userRotationInput
	if e := body(r, &in); e != nil {
		failureResponse(w, 422, e)
		return true
	}
	if parts[3] == "preview" {
		plan, _, e := a.rotationPlan(a.Store.Read(), parts[1], in)
		if e != nil {
			failureResponse(w, 422, e)
		} else {
			jsonResponse(w, 200, plan)
		}
		return true
	}
	if !in.Confirm {
		failureResponse(w, 422, errors.New("请先预览并明确确认此次轮换"))
		return true
	}
	if r.Header.Get("Idempotency-Key") == "" {
		failureResponse(w, 428, errors.New("缺少防重复操作标识，请刷新页面后重试"))
		return true
	}
	var result any
	e := a.updateMutation(r, in, &result, func(s *State) error {
		plan, version, e := a.rotationPlan(*s, parts[1], in)
		if e != nil {
			return e
		}
		if in.Version == "" || !equal(version, in.Version) {
			return rotationConflict{}
		}
		u := userByID(s, parts[1])
		if in.RotateToken {
			u.Token = randomToken(32)
		}
		if u.Credentials == nil {
			u.Credentials = map[string]string{}
		}
		for _, nid := range in.NodeIDs {
			n := nodeByID(s, nid)
			secret := credential(n.Protocol)
			if n.Protocol == "ss2022" {
				secret = ssKeyFor(ssMethod(n.ProtocolOptions))
			}
			u.Credentials[nid] = secret
		}
		servers := plan["serverIds"].([]string)
		if len(servers) > 0 {
			queue(s, servers, "轮换订阅节点认证 "+u.Name)
			if u.Required == nil {
				u.Required = map[string]int64{}
			}
			for _, sid := range servers {
				u.Required[sid] = serverByID(s, sid).Desired
			}
		}
		result = map[string]any{"id": u.ID, "rotatedToken": in.RotateToken, "rotatedNodeIds": append([]string{}, in.NodeIDs...), "serverIds": servers}
		return nil
	})
	if e != nil {
		status := 422
		var conflict rotationConflict
		if errors.As(e, &conflict) {
			status = 409
		}
		failureResponse(w, status, e)
	} else {
		jsonResponse(w, 200, result)
	}
	return true
}
