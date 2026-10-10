package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"go.uber.org/zap"
)

// EnsureConfig converges a Ziti config named `name` of type typeName to carry
// exactly `data`, and returns its id. It is the general form of
// CreateHostV1ConfigFixed and CreateInterceptV1ConfigFixed, whose data shapes
// are fixed to one address and one port: a network resource's intercept.v1
// carries several addresses and port ranges, and its host.v1 may forward
// whatever the dialer asked for within allowed lists.
//
// Get-or-create-or-update: OpenZiti enforces unique config names, so POSTing
// an existing name fails. A config that exists with the same data is reused
// untouched, so a reconcile pass over a converged service makes no write. One
// whose data differs is PATCHed in place (same id, still attached to its
// service).
//
// The comparison is semantic: both sides go through a JSON round trip, so
// numbers compare as numbers and key order does not matter.
func (zm *ZitiManager) EnsureConfig(ctx context.Context, name, typeName string, data map[string]interface{}) (string, error) {
	want, err := canonicalJSON(data)
	if err != nil {
		return "", fmt.Errorf("%s config %s: %w", typeName, name, err)
	}
	lookupPath := "/edge/management/v1/configs?filter=" + zitiFilterEquals("name", name)
	if body, status, lerr := zm.mgmtRequest("GET", lookupPath, nil); lerr == nil && status == http.StatusOK {
		var existing struct {
			Data []struct {
				ID           string          `json:"id"`
				Name         string          `json:"name"`
				ConfigTypeID string          `json:"configTypeId"`
				Data         json.RawMessage `json:"data"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &existing) == nil {
			for _, c := range existing.Data {
				if c.Name != name || c.ID == "" {
					continue
				}
				// A config of the right name but another type is not this
				// config: it is replaced, not patched (the data of one type
				// means something else under another).
				if c.ConfigTypeID != "" && c.ConfigTypeID != zm.resolveConfigTypeID(typeName) {
					_, ds, derr := zm.mgmtRequest("DELETE", "/edge/management/v1/configs/"+c.ID, nil)
					if derr != nil || (ds != http.StatusOK && ds != http.StatusNoContent) {
						return "", fmt.Errorf("replace %s config %s of type %s: status %d: %v", typeName, name, c.ConfigTypeID, ds, derr)
					}
					break
				}
				var have interface{}
				if json.Unmarshal(c.Data, &have) == nil && reflect.DeepEqual(have, want) {
					return c.ID, nil
				}
				patch, _ := json.Marshal(map[string]interface{}{"data": data})
				_, ps, perr := zm.mgmtRequest("PATCH", "/edge/management/v1/configs/"+c.ID, patch)
				if perr != nil {
					return "", fmt.Errorf("update %s config %s: %w", typeName, name, perr)
				}
				if ps != http.StatusOK && ps != http.StatusAccepted {
					return "", fmt.Errorf("unexpected status %d updating %s config %s", ps, typeName, name)
				}
				zm.logger.Info("Updated drifted config", zap.String("name", name), zap.String("type", typeName), zap.String("id", c.ID))
				return c.ID, nil
			}
		}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":         name,
		"configTypeId": zm.resolveConfigTypeID(typeName),
		"data":         data,
	})
	resp, status, err := zm.mgmtRequest("POST", "/edge/management/v1/configs", body)
	if err != nil {
		return "", fmt.Errorf("create %s config %s: %w", typeName, name, err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d creating %s config %s: %s", status, typeName, name, string(resp))
	}
	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &created); err != nil {
		return "", fmt.Errorf("parse %s config response: %w", typeName, err)
	}
	return created.Data.ID, nil
}

// canonicalJSON is v as it reads back after a JSON round trip.
func canonicalJSON(v interface{}) (interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
