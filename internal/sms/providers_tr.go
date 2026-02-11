// Package sms - Turkish SMS gateway providers
// Supports major Turkish operators and popular SMS aggregators
package sms

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// --- NetGSM Provider ---
// NetGSM is one of Turkey's most popular SMS gateways
// API Docs: https://www.netgsm.com.tr/dokuman/
// OTP endpoint: POST https://api.netgsm.com.tr/sms/send/otp

// NetGSMProvider implements SMS sending via NetGSM
type NetGSMProvider struct {
	userCode  string
	password  string
	msgHeader string
	client    *http.Client
	logger    *zap.Logger
}

// NewNetGSMProvider creates a new NetGSM SMS provider
func NewNetGSMProvider(userCode, password, msgHeader string, logger *zap.Logger) (*NetGSMProvider, error) {
	if userCode == "" || password == "" {
		return nil, fmt.Errorf("netgsm credentials required: usercode, password")
	}

	return &NetGSMProvider{
		userCode:  userCode,
		password:  password,
		msgHeader: msgHeader,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (n *NetGSMProvider) Name() string {
	return "netgsm"
}

func (n *NetGSMProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return n.sendOTP(ctx, phoneNumber, message)
}

// sendOTP uses NetGSM's dedicated OTP endpoint for faster delivery
func (n *NetGSMProvider) sendOTP(ctx context.Context, phoneNumber, message string) error {
	// NetGSM OTP API uses XML format
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<mainbody>
	<header>
		<usercode>%s</usercode>
		<password>%s</password>
		<msgheader>%s</msgheader>
	</header>
	<body>
		<msg><![CDATA[%s]]></msg>
		<no>%s</no>
	</body>
</mainbody>`, n.userCode, n.password, n.msgHeader, message, normalizePhoneTR(phoneNumber))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.netgsm.com.tr/sms/send/otp", strings.NewReader(xmlBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("netgsm request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	respStr := strings.TrimSpace(string(body))

	// NetGSM returns error codes as plain text: 20, 30, 40, 50, 51, 70, 80, 85
	// Success returns a job ID (numeric string > 100)
	if isNetGSMError(respStr) {
		n.logger.Error("NetGSM API error",
			zap.String("response", respStr),
			zap.String("to", maskPhone(phoneNumber)))
		return fmt.Errorf("netgsm error: %s", netgsmErrorMessage(respStr))
	}

	n.logger.Info("SMS sent via NetGSM OTP",
		zap.String("to", maskPhone(phoneNumber)),
		zap.String("job_id", respStr))

	return nil
}

func (n *NetGSMProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	// Use the regular SMS endpoint for non-OTP messages
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<mainbody>
	<header>
		<company dession="1">0</company>
		<usercode>%s</usercode>
		<password>%s</password>
		<type>1:n</type>
		<msgheader>%s</msgheader>
	</header>
	<body>
		<msg><![CDATA[%s]]></msg>
		<no>%s</no>
	</body>
</mainbody>`, n.userCode, n.password, n.msgHeader, message, normalizePhoneTR(phoneNumber))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.netgsm.com.tr/sms/send/get", strings.NewReader(xmlBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("netgsm request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	respStr := strings.TrimSpace(string(body))

	if isNetGSMError(respStr) {
		n.logger.Error("NetGSM API error",
			zap.String("response", respStr),
			zap.String("to", maskPhone(phoneNumber)))
		return fmt.Errorf("netgsm error: %s", netgsmErrorMessage(respStr))
	}

	n.logger.Info("SMS sent via NetGSM",
		zap.String("to", maskPhone(phoneNumber)),
		zap.String("job_id", respStr))

	return nil
}

func isNetGSMError(resp string) bool {
	errorCodes := []string{"20", "30", "40", "50", "51", "60", "70", "80", "85"}
	for _, code := range errorCodes {
		if resp == code {
			return true
		}
	}
	return false
}

func netgsmErrorMessage(code string) string {
	messages := map[string]string{
		"20": "post data format error",
		"30": "invalid credentials",
		"40": "sender ID not registered",
		"50": "recipient number invalid",
		"51": "message too long",
		"60": "OTP account settings error",
		"70": "invalid parameters",
		"80": "query limit exceeded",
		"85": "duplicate message within time limit",
	}
	if msg, ok := messages[code]; ok {
		return msg
	}
	return "unknown error code: " + code
}

// --- İleti Merkezi Provider ---
// İleti Merkezi is a popular Turkish SMS gateway
// API Docs: https://www.iletimerkezi.com/sms-api
// Endpoint: POST https://api.iletimerkezi.com/v1/send-sms/json

// IletiMerkeziProvider implements SMS sending via İleti Merkezi
type IletiMerkeziProvider struct {
	apiKey   string
	secret   string
	sender   string
	client   *http.Client
	logger   *zap.Logger
}

// NewIletiMerkeziProvider creates a new İleti Merkezi SMS provider
func NewIletiMerkeziProvider(apiKey, secret, sender string, logger *zap.Logger) (*IletiMerkeziProvider, error) {
	if apiKey == "" || secret == "" {
		return nil, fmt.Errorf("ileti merkezi credentials required: api_key, secret")
	}

	return &IletiMerkeziProvider{
		apiKey: apiKey,
		secret: secret,
		sender: sender,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (im *IletiMerkeziProvider) Name() string {
	return "ileti_merkezi"
}

func (im *IletiMerkeziProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return im.SendMessage(ctx, phoneNumber, message)
}

func (im *IletiMerkeziProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	payload := map[string]interface{}{
		"request": map[string]interface{}{
			"authentication": map[string]string{
				"key":    im.apiKey,
				"hash":   im.secret,
			},
			"order": map[string]interface{}{
				"sender":  im.sender,
				"sendDateTime": []string{},
				"message": map[string]interface{}{
					"text": message,
					"receipts": map[string]interface{}{
						"number": []string{normalizePhoneTR(phoneNumber)},
					},
				},
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.iletimerkezi.com/v1/send-sms/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := im.client.Do(req)
	if err != nil {
		return fmt.Errorf("ileti merkezi request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		im.logger.Error("İleti Merkezi API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("ileti merkezi returned status %d", resp.StatusCode)
	}

	// Parse response to check for API-level errors
	var result struct {
		Response struct {
			Status struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"status"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &result); err == nil {
		if result.Response.Status.Code != "200" && result.Response.Status.Code != "" {
			im.logger.Error("İleti Merkezi API error",
				zap.String("code", result.Response.Status.Code),
				zap.String("message", result.Response.Status.Message))
			return fmt.Errorf("ileti merkezi error %s: %s", result.Response.Status.Code, result.Response.Status.Message)
		}
	}

	im.logger.Info("SMS sent via İleti Merkezi",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- Verimor Provider ---
// Verimor is a well-documented Turkish SMS gateway
// API Docs: https://github.com/verimor/SMS-API
// Endpoint: POST https://sms.verimor.com.tr/v2/send.json

// VerimorProvider implements SMS sending via Verimor
type VerimorProvider struct {
	username   string
	password   string
	sourceAddr string
	client     *http.Client
	logger     *zap.Logger
}

// NewVerimorProvider creates a new Verimor SMS provider
func NewVerimorProvider(username, password, sourceAddr string, logger *zap.Logger) (*VerimorProvider, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("verimor credentials required: username, password")
	}

	return &VerimorProvider{
		username:   username,
		password:   password,
		sourceAddr: sourceAddr,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (v *VerimorProvider) Name() string {
	return "verimor"
}

func (v *VerimorProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return v.SendMessage(ctx, phoneNumber, message)
}

func (v *VerimorProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	payload := map[string]interface{}{
		"username":    v.username,
		"password":    v.password,
		"source_addr": v.sourceAddr,
		"messages": []map[string]string{
			{
				"msg":  message,
				"dest": normalizePhoneTR(phoneNumber),
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sms.verimor.com.tr/v2/send.json", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("verimor request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		v.logger.Error("Verimor API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("verimor error: %s", string(body))
	}

	// Success: returns campaign ID as plain text
	v.logger.Info("SMS sent via Verimor",
		zap.String("to", maskPhone(phoneNumber)),
		zap.String("campaign_id", strings.TrimSpace(string(body))))

	return nil
}

// --- Turkcell Mesajüssü Provider ---
// Turkcell's enterprise SMS platform
// API Docs: https://mesajussu.turkcell.com.tr/samples/MesajUssu-API-Dokumani-v2.2.pdf
// Uses session-based authentication with 24-hour token validity

// TurkcellProvider implements SMS sending via Turkcell Mesajüssü
type TurkcellProvider struct {
	username     string
	password     string
	sender       string
	baseURL      string
	client       *http.Client
	logger       *zap.Logger
	sessionToken string
	tokenExpiry  time.Time
	tokenMu      sync.Mutex
}

// NewTurkcellProvider creates a new Turkcell Mesajüssü SMS provider
func NewTurkcellProvider(username, password, sender string, logger *zap.Logger) (*TurkcellProvider, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("turkcell credentials required: username, password")
	}

	return &TurkcellProvider{
		username: username,
		password: password,
		sender:   sender,
		baseURL:  "https://mesajussu.turkcell.com.tr/api",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (t *TurkcellProvider) Name() string {
	return "turkcell"
}

// authenticate obtains or refreshes the session token
func (t *TurkcellProvider) authenticate(ctx context.Context) error {
	t.tokenMu.Lock()
	defer t.tokenMu.Unlock()

	// Reuse valid token (refresh 1 hour before expiry)
	if t.sessionToken != "" && time.Now().Before(t.tokenExpiry.Add(-1*time.Hour)) {
		return nil
	}

	payload := map[string]string{
		"username": t.username,
		"password": t.password,
	}
	jsonPayload, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+"/auth/login", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("turkcell auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("turkcell auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	t.sessionToken = authResp.Token
	// Default to 24 hours if expiresIn not provided
	if authResp.ExpiresIn > 0 {
		t.tokenExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)
	} else {
		t.tokenExpiry = time.Now().Add(24 * time.Hour)
	}

	t.logger.Info("Turkcell Mesajüssü authenticated",
		zap.Time("token_expiry", t.tokenExpiry))

	return nil
}

func (t *TurkcellProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return t.SendMessage(ctx, phoneNumber, message)
}

func (t *TurkcellProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	if err := t.authenticate(ctx); err != nil {
		return fmt.Errorf("turkcell authentication failed: %w", err)
	}

	payload := map[string]interface{}{
		"sender":  t.sender,
		"message": message,
		"numbers": []string{normalizePhoneTR(phoneNumber)},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+"/sms/send", bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	t.tokenMu.Lock()
	req.Header.Set("Authorization", "Bearer "+t.sessionToken)
	t.tokenMu.Unlock()

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("turkcell request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		t.logger.Error("Turkcell Mesajüssü API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("turkcell returned status %d: %s", resp.StatusCode, string(body))
	}

	t.logger.Info("SMS sent via Turkcell Mesajüssü",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- Vodafone Provider ---
// Vodafone Turkey SMS via GSMA OneAPI-based messaging hub
// API Docs: https://developer.vodafone.com/api-catalogue/sms-messaging-hub
// Requires enterprise agreement and OAuth2 credentials

// VodafoneProvider implements SMS sending via Vodafone Turkey
type VodafoneProvider struct {
	apiKey        string
	apiSecret     string
	senderAddress string
	baseURL       string
	client        *http.Client
	logger        *zap.Logger
	accessToken   string
	tokenExpiry   time.Time
	tokenMu       sync.Mutex
}

// NewVodafoneProvider creates a new Vodafone Turkey SMS provider
func NewVodafoneProvider(apiKey, apiSecret, senderAddress string, logger *zap.Logger) (*VodafoneProvider, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("vodafone credentials required: api_key, api_secret")
	}

	return &VodafoneProvider{
		apiKey:        apiKey,
		apiSecret:     apiSecret,
		senderAddress: senderAddress,
		baseURL:       "https://api.developer.vodafone.com",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (vf *VodafoneProvider) Name() string {
	return "vodafone"
}

// authenticate obtains an OAuth2 access token
func (vf *VodafoneProvider) authenticate(ctx context.Context) error {
	vf.tokenMu.Lock()
	defer vf.tokenMu.Unlock()

	if vf.accessToken != "" && time.Now().Before(vf.tokenExpiry.Add(-1*time.Minute)) {
		return nil
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", vf.apiKey)
	data.Set("client_secret", vf.apiSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vf.baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := vf.client.Do(req)
	if err != nil {
		return fmt.Errorf("vodafone auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vodafone auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	vf.accessToken = authResp.AccessToken
	vf.tokenExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)

	return nil
}

func (vf *VodafoneProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return vf.SendMessage(ctx, phoneNumber, message)
}

func (vf *VodafoneProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	if err := vf.authenticate(ctx); err != nil {
		return fmt.Errorf("vodafone authentication failed: %w", err)
	}

	// GSMA OneAPI format
	sender := url.PathEscape("tel:" + vf.senderAddress)
	endpoint := fmt.Sprintf("%s/v2/smsmessaging/outbound/%s/requests", vf.baseURL, sender)

	payload := map[string]interface{}{
		"outboundSMSMessageRequest": map[string]interface{}{
			"address":       []string{"tel:" + normalizePhoneTR(phoneNumber)},
			"senderAddress": "tel:" + vf.senderAddress,
			"outboundSMSTextMessage": map[string]string{
				"message": message,
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	vf.tokenMu.Lock()
	req.Header.Set("Authorization", "Bearer "+vf.accessToken)
	vf.tokenMu.Unlock()

	resp, err := vf.client.Do(req)
	if err != nil {
		return fmt.Errorf("vodafone request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		vf.logger.Error("Vodafone API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("vodafone returned status %d: %s", resp.StatusCode, string(body))
	}

	vf.logger.Info("SMS sent via Vodafone",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- Türk Telekom Provider ---
// Türk Telekom SMS API
// API Docs: https://developer.telekom.com/en/products/sms-api
// Uses OAuth2 authentication

// TurkTelekomProvider implements SMS sending via Türk Telekom
type TurkTelekomProvider struct {
	apiKey      string
	apiSecret   string
	sender      string
	baseURL     string
	client      *http.Client
	logger      *zap.Logger
	accessToken string
	tokenExpiry time.Time
	tokenMu     sync.Mutex
}

// NewTurkTelekomProvider creates a new Türk Telekom SMS provider
func NewTurkTelekomProvider(apiKey, apiSecret, sender string, logger *zap.Logger) (*TurkTelekomProvider, error) {
	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("turk telekom credentials required: api_key, api_secret")
	}

	return &TurkTelekomProvider{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		sender:    sender,
		baseURL:   "https://api.developer.telekom.com",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (tt *TurkTelekomProvider) Name() string {
	return "turk_telekom"
}

// authenticate obtains an OAuth2 access token
func (tt *TurkTelekomProvider) authenticate(ctx context.Context) error {
	tt.tokenMu.Lock()
	defer tt.tokenMu.Unlock()

	if tt.accessToken != "" && time.Now().Before(tt.tokenExpiry.Add(-1*time.Minute)) {
		return nil
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", tt.apiKey)
	data.Set("client_secret", tt.apiSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tt.baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tt.client.Do(req)
	if err != nil {
		return fmt.Errorf("turk telekom auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("turk telekom auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %w", err)
	}

	tt.accessToken = authResp.AccessToken
	tt.tokenExpiry = time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)

	return nil
}

func (tt *TurkTelekomProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return tt.SendMessage(ctx, phoneNumber, message)
}

func (tt *TurkTelekomProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	if err := tt.authenticate(ctx); err != nil {
		return fmt.Errorf("turk telekom authentication failed: %w", err)
	}

	payload := map[string]interface{}{
		"outboundSMSMessageRequest": map[string]interface{}{
			"address":       []string{"tel:" + normalizePhoneTR(phoneNumber)},
			"senderAddress": "tel:" + tt.sender,
			"outboundSMSTextMessage": map[string]string{
				"message": message,
			},
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	sender := url.PathEscape("tel:" + tt.sender)
	endpoint := fmt.Sprintf("%s/v2/smsmessaging/outbound/%s/requests", tt.baseURL, sender)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	tt.tokenMu.Lock()
	req.Header.Set("Authorization", "Bearer "+tt.accessToken)
	tt.tokenMu.Unlock()

	resp, err := tt.client.Do(req)
	if err != nil {
		return fmt.Errorf("turk telekom request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		tt.logger.Error("Türk Telekom API error",
			zap.Int("status", resp.StatusCode),
			zap.String("response", string(body)))
		return fmt.Errorf("turk telekom returned status %d: %s", resp.StatusCode, string(body))
	}

	tt.logger.Info("SMS sent via Türk Telekom",
		zap.String("to", maskPhone(phoneNumber)),
		zap.Int("status", resp.StatusCode))

	return nil
}

// --- Mutlucell Provider ---
// Mutlucell is a Turkish SMS aggregator
// API Docs: https://www.mutlucell.com.tr/api
// Uses XML-based API

// MutlucellProvider implements SMS sending via Mutlucell
type MutlucellProvider struct {
	username string
	password string
	apiKey   string
	sender   string
	client   *http.Client
	logger   *zap.Logger
}

// NewMutlucellProvider creates a new Mutlucell SMS provider
func NewMutlucellProvider(username, password, apiKey, sender string, logger *zap.Logger) (*MutlucellProvider, error) {
	if apiKey == "" && (username == "" || password == "") {
		return nil, fmt.Errorf("mutlucell credentials required: api_key or username+password")
	}

	return &MutlucellProvider{
		username: username,
		password: password,
		apiKey:   apiKey,
		sender:   sender,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}, nil
}

func (m *MutlucellProvider) Name() string {
	return "mutlucell"
}

func (m *MutlucellProvider) SendOTP(ctx context.Context, phoneNumber, code string) error {
	message := fmt.Sprintf("Dogrulama kodunuz: %s", code)
	return m.SendMessage(ctx, phoneNumber, message)
}

type mutlucellRequest struct {
	XMLName  xml.Name `xml:"smspack"`
	Ka       string   `xml:"ka,attr"`
	Pwd      string   `xml:"pwd,attr"`
	Org      string   `xml:"org,attr"`
	APIKey   string   `xml:"apiKey,attr,omitempty"`
	Mesaj    mutlucellMessage
}

type mutlucellMessage struct {
	XMLName xml.Name `xml:"mesaj"`
	Metin   string   `xml:"metin"`
	Nums    string   `xml:"nums"`
}

func (m *MutlucellProvider) SendMessage(ctx context.Context, phoneNumber, message string) error {
	xmlReq := mutlucellRequest{
		Ka:     m.username,
		Pwd:    m.password,
		Org:    m.sender,
		APIKey: m.apiKey,
		Mesaj: mutlucellMessage{
			Metin: message,
			Nums:  normalizePhoneTR(phoneNumber),
		},
	}

	xmlBody, err := xml.Marshal(xmlReq)
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://smsgw.mutlucell.com/smsgw-ws/sndblkex", bytes.NewReader(xmlBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/xml")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("mutlucell request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	respStr := strings.TrimSpace(string(body))

	// Mutlucell returns $xx for errors, positive number for success
	if strings.HasPrefix(respStr, "$") {
		m.logger.Error("Mutlucell API error",
			zap.String("response", respStr),
			zap.String("to", maskPhone(phoneNumber)))
		return fmt.Errorf("mutlucell error: %s", mutlucellErrorMessage(respStr))
	}

	m.logger.Info("SMS sent via Mutlucell",
		zap.String("to", maskPhone(phoneNumber)),
		zap.String("campaign_id", respStr))

	return nil
}

func mutlucellErrorMessage(code string) string {
	messages := map[string]string{
		"$20":  "post error",
		"$21":  "XML format error",
		"$22":  "invalid credentials",
		"$23":  "insufficient credits",
		"$24":  "sender not registered",
		"$25":  "XML structure error",
		"$26":  "invalid phone number",
		"$27":  "restricted message content",
		"$28":  "internal error",
		"$30":  "invalid characters in message",
		"$100": "system error",
	}
	if msg, ok := messages[code]; ok {
		return msg
	}
	return "unknown error: " + code
}

// --- Utility Functions for Turkish providers ---

// normalizePhoneTR normalizes a phone number to Turkish format (905XXXXXXXXX)
func normalizePhoneTR(phone string) string {
	// Remove all non-digit characters
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)

	// Handle various formats
	switch {
	case strings.HasPrefix(digits, "90") && len(digits) == 12:
		// Already in 90XXXXXXXXXX format
		return digits
	case strings.HasPrefix(digits, "0") && len(digits) == 11:
		// 0XXXXXXXXXX -> 90XXXXXXXXXX
		return "9" + digits
	case len(digits) == 10 && (strings.HasPrefix(digits, "5") || strings.HasPrefix(digits, "4")):
		// 5XXXXXXXXX -> 905XXXXXXXXX
		return "90" + digits
	case strings.HasPrefix(digits, "+90"):
		return digits[1:] // Remove +
	default:
		return digits
	}
}
