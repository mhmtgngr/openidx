// Package main is the entry point for the OpenIDX Demo App.
// It displays the authenticated user's identity from X-Forwarded-* headers
// set by APISIX forward-auth or passed through BrowZer.
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

//go:embed static/index.html
var staticFS embed.FS

var htmlTemplate *template.Template

func init() {
	raw, _ := staticFS.ReadFile("static/index.html")
	// We inject identity data as a JS variable before </script>
	htmlTemplate = template.Must(template.New("index").Parse(string(raw)))
}

type identityData struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Roles      string `json:"roles"`
	RiskScore  string `json:"risk_score,omitempty"`
	Route      string `json:"route,omitempty"`
	ServerTime string `json:"server_time"`
}

func getIdentity(r *http.Request) *identityData {
	userID := r.Header.Get("X-Forwarded-User")
	if userID == "" {
		return nil
	}
	return &identityData{
		UserID:     userID,
		Email:      r.Header.Get("X-Forwarded-Email"),
		Name:       r.Header.Get("X-Forwarded-Name"),
		Roles:      r.Header.Get("X-Forwarded-Roles"),
		RiskScore:  r.Header.Get("X-Risk-Score"),
		Route:      r.Header.Get("X-Forwarded-Route"),
		ServerTime: time.Now().UTC().Format(time.RFC3339),
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/demo/" && r.URL.Path != "/demo" {
		http.NotFound(w, r)
		return
	}

	id := getIdentity(r)
	var dataJSON string
	if id != nil {
		b, _ := json.Marshal(id)
		dataJSON = string(b)
	} else {
		dataJSON = "null"
	}

	raw, _ := staticFS.ReadFile("static/index.html")
	html := string(raw)

	// Inject identity data as a JS variable
	injection := fmt.Sprintf(`<script>window.__IDENTITY_DATA__ = %s;</script>`, dataJSON)
	html = strings.Replace(html, `<script>`, injection+"\n  <script>", 1)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
	id := getIdentity(r)
	resp := map[string]interface{}{
		"server_time": time.Now().UTC().Format(time.RFC3339),
	}
	if id != nil {
		resp["authenticated"] = true
		resp["user_id"] = id.UserID
		resp["email"] = id.Email
		resp["name"] = id.Name
		resp["roles"] = id.Roles
		if id.RiskScore != "" {
			resp["risk_score"] = id.RiskScore
		}
		if id.Route != "" {
			resp["route"] = id.Route
		}
	} else {
		resp["authenticated"] = false
		resp["message"] = "No identity headers present. Access via APISIX forward-auth or BrowZer."
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "demo-app"})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/demo", handleIndex)
	mux.HandleFunc("/demo/", handleIndex)
	mux.HandleFunc("/api/whoami", handleWhoami)
	mux.HandleFunc("/health", handleHealth)

	fmt.Println("OpenIDX Demo App listening on :8090")
	if err := http.ListenAndServe(":8090", mux); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
