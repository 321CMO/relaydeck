package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/321CMO/relaydeck/internal/panel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

// Small wire adapter for the pinned upstream QueryStats protobuf schema.
// https://github.com/SagerNet/sing-box/blob/v1.14.3/experimental/v2rayapi/stats.proto
// The request is empty: no reset, no pattern, all counters. Only the local API is used.
type statsWire struct{}

func (statsWire) Name() string                  { return "proto" }
func (statsWire) Marshal(v any) ([]byte, error) { return *v.(*[]byte), nil }
func (statsWire) Unmarshal(b []byte, v any) error {
	*v.(*[]byte) = append([]byte(nil), b...)
	return nil
}

func decodeStats(b []byte) (map[string]panel.TrafficCounter, error) {
	result := map[string]panel.TrafficCounter{}
	for len(b) > 0 {
		n, typ, k := protowire.ConsumeTag(b)
		if k < 0 {
			return nil, errors.New("invalid stats protobuf")
		}
		b = b[k:]
		if n != 1 || typ != protowire.BytesType {
			k = protowire.ConsumeFieldValue(n, typ, b)
			if k < 0 {
				return nil, errors.New("invalid stats field")
			}
			b = b[k:]
			continue
		}
		entry, k := protowire.ConsumeBytes(b)
		if k < 0 {
			return nil, errors.New("invalid stats entry")
		}
		b = b[k:]
		name := ""
		var value int64
		for len(entry) > 0 {
			f, t, k := protowire.ConsumeTag(entry)
			if k < 0 {
				return nil, errors.New("invalid counter")
			}
			entry = entry[k:]
			if f == 1 && t == protowire.BytesType {
				v, k := protowire.ConsumeString(entry)
				if k < 0 {
					return nil, errors.New("invalid name")
				}
				name = v
				entry = entry[k:]
			} else if f == 2 && t == protowire.VarintType {
				v, k := protowire.ConsumeVarint(entry)
				if k < 0 || v > 1<<53 {
					return nil, errors.New("invalid bytes")
				}
				value = int64(v)
				entry = entry[k:]
			} else {
				k = protowire.ConsumeFieldValue(f, t, entry)
				if k < 0 {
					return nil, errors.New("invalid field")
				}
				entry = entry[k:]
			}
		}
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		v := result[parts[1]]
		if parts[3] == "uplink" {
			v.Upload = value
		} else if parts[3] == "downlink" {
			v.Download = value
		}
		result[parts[1]] = v
	}
	return result, nil
}
func readStats(ctx context.Context) (map[string]panel.TrafficCounter, error) {
	conn, e := grpc.NewClient("127.0.0.1:10085", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.ForceCodec(statsWire{}), grpc.MaxCallRecvMsgSize(1<<20)))
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	var request, response []byte
	if e = conn.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &request, &response); e != nil {
		return nil, e
	}
	return decodeStats(response)
}

type trafficLedger struct {
	panel.TrafficReport
	Generation string                          `json:"generation"`
	Baseline   map[string]panel.TrafficCounter `json:"baseline"`
}

func (a *Agent) sampleTraffic(ctx context.Context) *panel.TrafficReport {
	if a.current == nil || !a.alive() || a.current.TrafficUsers == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	values, e := readStats(ctx)
	if e != nil {
		return nil
	}
	path := filepath.Join(a.Dir, "traffic.json")
	var ledger trafficLedger
	if b, e := os.ReadFile(path); e == nil {
		if json.Unmarshal(b, &ledger) != nil || ledger.Stream == "" || ledger.Users == nil {
			return nil
		}
	} else if !os.IsNotExist(e) {
		return nil
	}
	if ledger.Stream == "" {
		b := make([]byte, 24)
		if _, e = rand.Read(b); e != nil {
			return nil
		}
		ledger.TrafficReport = panel.TrafficReport{Stream: base64.RawURLEncoding.EncodeToString(b), Since: time.Now().UTC(), Users: map[string]panel.TrafficCounter{}}
	}
	if ledger.Generation != a.generation {
		ledger.Generation = a.generation
		ledger.Baseline = map[string]panel.TrafficCounter{}
	}
	for _, id := range a.current.TrafficUsers {
		v := values[id]
		old := ledger.Baseline[id]
		total := ledger.Users[id]
		// Non-reset counters are scoped to a core generation, and saved with totals.
		total.Upload += max(v.Upload-old.Upload, 0)
		total.Download += max(v.Download-old.Download, 0)
		ledger.Users[id] = total
		ledger.Baseline[id] = v
	}
	ledger.Observed = time.Now().UTC()
	b, e := json.Marshal(ledger)
	if e != nil || atomicWrite(path, b) != nil {
		return nil
	}
	return &ledger.TrafficReport
}
