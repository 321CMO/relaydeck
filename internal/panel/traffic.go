package panel

import (
	"errors"
	"math"
	"time"
)

type TrafficCounter struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}
type TrafficReport struct {
	Stream   string                    `json:"stream"`
	Since    time.Time                 `json:"since"`
	Observed time.Time                 `json:"observed"`
	Users    map[string]TrafficCounter `json:"users"`
}

// High-water marks and user totals are committed in the same encrypted transaction.
// Replayed reports, retries and a center restore cannot add the same bytes twice.
func ingestTraffic(s *State, server *Server, report *TrafficReport) error {
	if report == nil {
		return nil
	}
	if len(report.Stream) < 24 || len(report.Stream) > 64 || len(report.Users) > 2000 || report.Since.IsZero() || report.Observed.Before(report.Since) || report.Observed.After(time.Now().Add(5*time.Minute)) {
		return errors.New("流量报告无效")
	}
	if server.TrafficCursors == nil {
		server.TrafficCursors = map[string]map[string]TrafficCounter{}
	}
	cursor, exists := server.TrafficCursors[report.Stream]
	if !exists {
		if len(server.TrafficCursors) >= 1024 {
			return errors.New("统计来源过多，请检查 Agent 数据目录")
		}
		cursor = map[string]TrafficCounter{}
		server.TrafficCursors[report.Stream] = cursor
	}
	for id, value := range report.Users {
		if value.Upload < 0 || value.Download < 0 || value.Upload > 1<<53 || value.Download > 1<<53 {
			return errors.New("流量计数无效")
		}
		u := userByID(s, id)
		if u == nil {
			continue
		}
		old := cursor[id]
		up, down := max(value.Upload-old.Upload, 0), max(value.Download-old.Download, 0)
		if u.Upload > math.MaxInt64-up || u.Download > math.MaxInt64-down || u.Used > math.MaxInt64-up-down {
			return errors.New("流量计数超出范围")
		}
		u.Upload += up
		u.Download += down
		u.Used += up + down
		if u.UsageSince.IsZero() || report.Since.Before(u.UsageSince) {
			u.UsageSince = report.Since
		}
		if report.Observed.After(u.UsageUpdated) {
			u.UsageUpdated = report.Observed
		}
		cursor[id] = TrafficCounter{max(old.Upload, value.Upload), max(old.Download, value.Download)}
	}
	server.TrafficLastSeen = maxTime(server.TrafficLastSeen, report.Observed)
	return nil
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
