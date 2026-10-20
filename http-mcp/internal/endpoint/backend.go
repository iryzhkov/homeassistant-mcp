package endpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

var errUnavailable = errors.New("entity unavailable")
var errUncertain = errors.New("write outcome uncertain; reconcile desired state using a separately authorized read; no automatic retry")

type backend struct {
	url, token string
	client     *http.Client
}
type EntityState struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	State             string `json:"state"`
	BrightnessPercent *int   `json:"brightness_percent,omitempty"`
	Unit              string `json:"unit,omitempty"`
	LastChanged       string `json:"last_changed,omitempty"`
	LastUpdated       string `json:"last_updated,omitempty"`
}
type writeResult struct {
	Outcome                string `json:"outcome"`
	PhysicalStateConfirmed bool   `json:"physical_state_confirmed"`
}

func (b *backend) read(ctx context.Context, entity Entity) (EntityState, error) {
	var out EntityState
	// IDs have already passed the signed grant AND registry intersection.
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, b.url+"/api/states/"+entity.ID, nil)
	if e != nil {
		return out, errUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	res, e := b.client.Do(req)
	if e != nil {
		return out, errUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return out, errUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if e != nil || len(raw) > maxBody {
		return out, errUnavailable
	}
	var state struct {
		EntityID   string `json:"entity_id"`
		State      string `json:"state"`
		Attributes struct {
			Brightness *float64 `json:"brightness"`
			Unit       string   `json:"unit_of_measurement"`
		} `json:"attributes"`
		LastChanged string `json:"last_changed"`
		LastUpdated string `json:"last_updated"`
	}
	if json.Unmarshal(raw, &state) != nil || state.EntityID != entity.ID || !safeText(state.State, 128) {
		return out, errUnavailable
	}
	out = EntityState{ID: entity.ID, Name: entity.Name, State: state.State}
	if strings.HasPrefix(entity.ID, "light.") && state.Attributes.Brightness != nil {
		n := *state.Attributes.Brightness
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= 255 {
			p := int(math.Round(n * 100 / 255))
			out.BrightnessPercent = &p
		}
	}
	if strings.HasPrefix(entity.ID, "sensor.") && safeText(state.Attributes.Unit, 24) {
		out.Unit = state.Attributes.Unit
	}
	if _, e := time.Parse(time.RFC3339Nano, state.LastChanged); e == nil && len(state.LastChanged) <= 40 {
		out.LastChanged = state.LastChanged
	}
	if _, e := time.Parse(time.RFC3339Nano, state.LastUpdated); e == nil && len(state.LastUpdated) <= 40 {
		out.LastUpdated = state.LastUpdated
	}
	return out, nil
}
func (b *backend) set(ctx context.Context, entity Entity, power string, brightness *int) (writeResult, error) {
	domain := strings.Split(entity.ID, ".")[0]
	body := struct {
		EntityID   string `json:"entity_id"`
		Brightness *int   `json:"brightness,omitempty"`
	}{EntityID: entity.ID}
	if brightness != nil {
		n := int(math.Round(float64(*brightness) * 255 / 100))
		body.Brightness = &n
	}
	raw, _ := json.Marshal(body)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, b.url+"/api/services/"+domain+"/turn_"+power, bytes.NewReader(raw))
	if e != nil {
		return writeResult{}, errUncertain
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	// No application retries or idempotency key. Go's Transport may resend on
	// a reused connection when nothing was written and GetBody is available.
	// Any error reaching us remains uncertain and is never retried here.
	res, e := b.client.Do(req)
	if e != nil {
		return writeResult{}, errUncertain
	}
	defer res.Body.Close()
	// HA may return unrelated changed states, attributes and user context. Consume
	// a bounded body solely to detect completion; never decode or return it.
	n, e := io.Copy(io.Discard, io.LimitReader(res.Body, maxBody+1))
	if e != nil || n > maxBody || res.StatusCode != http.StatusOK {
		return writeResult{}, errUncertain
	}
	return writeResult{Outcome: "accepted", PhysicalStateConfirmed: false}, nil
}
