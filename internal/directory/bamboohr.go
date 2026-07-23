package directory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// BambooHRConnector reads the employee directory from BambooHR's REST API and
// maps it to UserRecords for the JML sync. BambooHR is the system of record:
// an employee present in the directory is a joiner/active user; one that has
// disappeared (or whose status is Terminated) is a leaver.
//
// Auth: HTTP Basic with the API key as the username and any non-empty password
// (BambooHR's documented scheme). All calls request JSON via the Accept header.
type BambooHRConnector struct {
	cfg     HRISConfig
	baseURL string
	logger  *zap.Logger
	client  *http.Client
}

// NewBambooHRConnector builds a connector. It resolves the API base URL from
// the config: an explicit BaseURL wins, otherwise the standard BambooHR gateway
// for the configured subdomain.
func NewBambooHRConnector(cfg HRISConfig, logger *zap.Logger) *BambooHRConnector {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		base = "https://api.bamboohr.com/api/gateway.php/" + strings.TrimSpace(cfg.Subdomain)
	}
	return &BambooHRConnector{
		cfg:     cfg,
		baseURL: base,
		logger:  logger.With(zap.String("component", "bamboohr-connector")),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *BambooHRConnector) authHeader() string {
	// BambooHR: Basic base64(apiKey + ":x").
	raw := c.cfg.APIKey + ":x"
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

func (c *BambooHRConnector) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("bamboohr %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("bamboohr %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode bamboohr response: %w", err)
		}
	}
	return nil
}

// TestConnection verifies credentials by fetching the employee directory head.
func (c *BambooHRConnector) TestConnection(ctx context.Context) error {
	if c.cfg.APIKey == "" {
		return fmt.Errorf("bamboohr api_key is required")
	}
	if c.cfg.Subdomain == "" && c.cfg.BaseURL == "" {
		return fmt.Errorf("bamboohr subdomain is required")
	}
	var dir bambooDirectory
	if err := c.get(ctx, "/v1/employees/directory", &dir); err != nil {
		return err
	}
	c.logger.Info("BambooHR connection test successful", zap.Int("employees", len(dir.Employees)))
	return nil
}

// SearchUsers fetches the full employee directory and maps it to UserRecords.
func (c *BambooHRConnector) SearchUsers(ctx context.Context) ([]UserRecord, error) {
	var dir bambooDirectory
	if err := c.get(ctx, "/v1/employees/directory", &dir); err != nil {
		return nil, err
	}
	records := make([]UserRecord, 0, len(dir.Employees))
	for _, e := range dir.Employees {
		rec := c.mapEmployee(e)
		if rec.Email == "" && rec.EmployeeNumber == "" {
			continue // unusable without a stable identifier
		}
		records = append(records, rec)
	}
	c.logger.Debug("BambooHR directory fetched", zap.Int("count", len(records)))
	return records, nil
}

// SearchGroups is not supported for HRIS sources (departments are attributes,
// not group objects). Returns an empty set so the DirectoryConnector contract
// holds.
func (c *BambooHRConnector) SearchGroups(ctx context.Context) ([]GroupRecord, error) {
	return nil, nil
}

// mapEmployee converts a BambooHR directory entry into a UserRecord.
func (c *BambooHRConnector) mapEmployee(e bambooEmployee) UserRecord {
	rec := UserRecord{
		ExternalID:      e.ID,
		EmployeeNumber:  firstNonEmpty(e.EmployeeNumber, e.ID),
		Email:           strings.TrimSpace(e.WorkEmail),
		FirstName:       e.FirstName,
		LastName:        e.LastName,
		DisplayName:     e.DisplayName,
		JobTitle:        e.JobTitle,
		Department:      e.Department,
		ManagerExternal: e.SupervisorEID,
		HireDate:        normalizeDate(e.HireDate),
		TerminationDate: normalizeDate(e.TerminationDate),
	}
	rec.EmploymentStatus = deriveStatus(e.Status, rec.TerminationDate)
	// Username: email by default, employee number when configured or email is absent.
	if c.cfg.UsernameField == "employee_number" || rec.Email == "" {
		rec.Username = rec.EmployeeNumber
	} else {
		rec.Username = rec.Email
	}
	if rec.DisplayName == "" {
		rec.DisplayName = strings.TrimSpace(e.FirstName + " " + e.LastName)
	}
	return rec
}

// deriveStatus normalizes BambooHR's status string + termination date into the
// employment_status enum used by the sync (active|terminated|on_leave|pending).
func deriveStatus(raw, terminationDate string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "terminat"):
		return "terminated"
	case strings.Contains(s, "leave"):
		return "on_leave"
	case s == "active":
		return "active"
	}
	// Directory listings omit an explicit status; a set termination date in the
	// past means terminated, otherwise treat as active (present in directory).
	if terminationDate != "" {
		if t, err := time.Parse("2006-01-02", terminationDate); err == nil && !t.After(time.Now()) {
			return "terminated"
		}
	}
	return "active"
}

// normalizeDate trims BambooHR's date (YYYY-MM-DD) and drops sentinel/empty
// values like "0000-00-00".
func normalizeDate(d string) string {
	d = strings.TrimSpace(d)
	if d == "" || strings.HasPrefix(d, "0000") {
		return ""
	}
	if len(d) >= 10 {
		return d[:10]
	}
	return d
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// bambooDirectory is the /v1/employees/directory response.
type bambooDirectory struct {
	Employees []bambooEmployee `json:"employees"`
}

// bambooEmployee models the directory fields OpenIDX consumes. BambooHR returns
// additional fields; unknown ones are ignored.
type bambooEmployee struct {
	ID              string `json:"id"`
	EmployeeNumber  string `json:"employeeNumber"`
	DisplayName     string `json:"displayName"`
	FirstName       string `json:"firstName"`
	LastName        string `json:"lastName"`
	WorkEmail       string `json:"workEmail"`
	JobTitle        string `json:"jobTitle"`
	Department      string `json:"department"`
	SupervisorEID   string `json:"supervisorEId"`
	Status          string `json:"status"`
	HireDate        string `json:"hireDate"`
	TerminationDate string `json:"terminationDate"`
}
