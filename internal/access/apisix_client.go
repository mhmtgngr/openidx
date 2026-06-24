package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// APISIXClient is a thin Admin API client for managing routes.
type APISIXClient struct {
	adminURL string
	adminKey string
	http     *http.Client
}

func NewAPISIXClient(adminURL, adminKey string) *APISIXClient {
	return &APISIXClient{adminURL: adminURL, adminKey: adminKey, http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *APISIXClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var r *bytes.Reader
	if body != nil {
		r = bytes.NewReader(body)
	} else {
		r = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.adminURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.adminKey)
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

// PutRoute upserts a route by name (Admin API PUT is idempotent).
func (c *APISIXClient) PutRoute(ctx context.Context, name string, body []byte) error {
	resp, err := c.do(ctx, http.MethodPut, "/apisix/admin/routes/"+name, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("PUT route %s: status %d", name, resp.StatusCode)
	}
	return nil
}

// DeleteRoute removes a route by name (404 tolerated as already-gone).
func (c *APISIXClient) DeleteRoute(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/apisix/admin/routes/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("DELETE route %s: status %d", name, resp.StatusCode)
}

// ListRouteNames returns the ids of all configured routes.
func (c *APISIXClient) ListRouteNames(ctx context.Context) ([]string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/apisix/admin/routes", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LIST routes: status %d", resp.StatusCode)
	}
	var parsed struct {
		List []struct {
			Value struct {
				ID string `json:"id"`
			} `json:"value"`
		} `json:"list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(parsed.List))
	for _, it := range parsed.List {
		names = append(names, it.Value.ID)
	}
	return names, nil
}
