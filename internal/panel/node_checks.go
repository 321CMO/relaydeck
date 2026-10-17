package panel

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/321CMO/relaydeck/internal/nodecheck"
)

type nodeCheckJob struct {
	nodecheck.Request
	ServerID string            `json:"serverId"`
	Status   string            `json:"status"`
	Created  time.Time         `json:"created"`
	Result   *nodecheck.Result `json:"result,omitempty"`
}
type nodeChecks struct {
	mu   sync.Mutex
	jobs map[string]*nodeCheckJob
}

func (c *nodeChecks) prune(now time.Time) {
	if c.jobs == nil {
		c.jobs = map[string]*nodeCheckJob{}
	}
	for id, j := range c.jobs {
		if now.Sub(j.Created) > 10*time.Minute {
			delete(c.jobs, id)
		} else if j.Status == "pending" && now.Sub(j.Created) > 90*time.Second {
			j.Status = "timeout"
		}
	}
}
func (a *App) nodeCheckAPI(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) < 2 || parts[0] != "nodes" || parts[1] != "checks" {
		return false
	}
	if len(parts) == 2 && r.Method == "POST" {
		var in struct {
			ServerID string `json:"serverId"`
			Target   string `json:"target"`
			SNI      string `json:"sni"`
		}
		if e := body(r, &in); e != nil {
			failureResponse(w, 422, e)
			return true
		}
		q := nodecheck.Request{ID: newID("check"), Target: in.Target, SNI: in.SNI}
		if e := nodecheck.Validate(q); e != nil {
			failureResponse(w, 422, e)
			return true
		}
		s := a.Store.Read()
		srv := serverByID(&s, in.ServerID)
		if srv == nil || srv.MachineID == "" || time.Since(srv.LastSeen) > 45*time.Second {
			failureResponse(w, 422, errors.New("请先登记服务器并等待 Agent 在线，再从该 VPS 检测"))
			return true
		}
		c := &a.nodeChecks
		c.mu.Lock()
		defer c.mu.Unlock()
		now := time.Now().UTC()
		c.prune(now)
		pending := 0
		for _, j := range c.jobs {
			if j.Status == "pending" {
				pending++
				if j.ServerID == in.ServerID {
					failureResponse(w, 409, errors.New("这台服务器已有检测正在进行，请等待完成"))
					return true
				}
			}
		}
		if pending >= 8 || len(c.jobs) >= 64 {
			failureResponse(w, 429, errors.New("检测任务较多，请稍后再试"))
			return true
		}
		j := &nodeCheckJob{Request: q, ServerID: in.ServerID, Status: "pending", Created: now}
		c.jobs[q.ID] = j
		jsonResponse(w, 202, j)
		return true
	}
	if len(parts) == 3 && r.Method == "GET" {
		c := &a.nodeChecks
		c.mu.Lock()
		defer c.mu.Unlock()
		c.prune(time.Now())
		j := c.jobs[parts[2]]
		if j == nil {
			failureResponse(w, 404, errors.New("检测记录已过期，请重新检测"))
		} else {
			jsonResponse(w, 200, j)
		}
		return true
	}
	failureResponse(w, 405, errors.New("请求方式无效"))
	return true
}

// Called only after the reporting Agent has authenticated successfully.
func (c *nodeChecks) sync(server string, results []nodecheck.Result) []nodecheck.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(time.Now())
	for _, v := range results {
		j := c.jobs[v.ID]
		if j == nil || j.ServerID != server || j.Status != "pending" || len(v.Message) > 512 || len(v.Stage) > 32 || len(v.ALPN) > 255 {
			continue
		}
		v.Checked = time.Now().UTC()
		j.Result = &v
		j.Status = "failed"
		if v.Success {
			j.Status = "passed"
		}
	}
	for _, j := range c.jobs {
		if j.ServerID == server && j.Status == "pending" {
			return []nodecheck.Request{j.Request}
		}
	}
	return nil
}
