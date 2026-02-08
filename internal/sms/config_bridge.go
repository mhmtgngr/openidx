package sms

// DBSMSSettings represents SMS settings as stored in the database (system_settings table).
// Used by both admin-api (for CRUD) and identity-service (for config watcher).
type DBSMSSettings struct {
	Enabled       bool              `json:"enabled"`
	Provider      string            `json:"provider"`
	MessagePrefix string            `json:"message_prefix"`
	OTPLength     int               `json:"otp_length"`
	OTPExpiry     int               `json:"otp_expiry"`
	MaxAttempts   int               `json:"max_attempts"`
	Credentials   map[string]string `json:"credentials"`
}

// DefaultDBSMSSettings returns default SMS settings for new installations.
func DefaultDBSMSSettings() *DBSMSSettings {
	return &DBSMSSettings{
		Enabled:       false,
		Provider:      "mock",
		MessagePrefix: "OpenIDX",
		OTPLength:     6,
		OTPExpiry:     300,
		MaxAttempts:   3,
		Credentials:   map[string]string{},
	}
}

// ToConfig converts database SMS settings to the sms.Config struct used by NewService.
func (s *DBSMSSettings) ToConfig() Config {
	c := Config{
		Provider:      s.Provider,
		Enabled:       s.Enabled,
		MessagePrefix: s.MessagePrefix,
	}
	if s.Credentials == nil {
		return c
	}

	creds := s.Credentials

	// Twilio
	c.TwilioSID = creds["twilio_sid"]
	c.TwilioToken = creds["twilio_token"]
	c.TwilioFrom = creds["twilio_from"]

	// AWS SNS
	c.AWSRegion = creds["aws_region"]
	c.AWSAccessKey = creds["aws_access_key"]
	c.AWSSecretKey = creds["aws_secret_key"]

	// NetGSM
	c.NetGSMUserCode = creds["netgsm_usercode"]
	c.NetGSMPassword = creds["netgsm_password"]
	c.NetGSMHeader = creds["netgsm_header"]

	// İleti Merkezi
	c.IletiMerkeziKey = creds["iletimerkezi_key"]
	c.IletiMerkeziSecret = creds["iletimerkezi_secret"]
	c.IletiMerkeziSender = creds["iletimerkezi_sender"]

	// Verimor
	c.VerimorUsername = creds["verimor_username"]
	c.VerimorPassword = creds["verimor_password"]
	c.VerimorSourceAddr = creds["verimor_source_addr"]

	// Turkcell
	c.TurkcellUsername = creds["turkcell_username"]
	c.TurkcellPassword = creds["turkcell_password"]
	c.TurkcellSender = creds["turkcell_sender"]

	// Vodafone
	c.VodafoneAPIKey = creds["vodafone_api_key"]
	c.VodafoneSecret = creds["vodafone_secret"]
	c.VodafoneSender = creds["vodafone_sender"]

	// Türk Telekom
	c.TurkTelekomAPIKey = creds["turktelekom_api_key"]
	c.TurkTelekomSecret = creds["turktelekom_secret"]
	c.TurkTelekomSender = creds["turktelekom_sender"]

	// Mutlucell
	c.MutlucellUsername = creds["mutlucell_username"]
	c.MutlucellPassword = creds["mutlucell_password"]
	c.MutlucellAPIKey = creds["mutlucell_api_key"]
	c.MutlucellSender = creds["mutlucell_sender"]

	// Webhook
	c.WebhookURL = creds["webhook_url"]
	c.WebhookAPIKey = creds["webhook_api_key"]

	return c
}

// MaskedValue is the sentinel returned for sensitive fields in GET responses.
const MaskedValue = "********"

// SensitiveFields maps each provider to its sensitive credential keys.
var SensitiveFields = map[string][]string{
	"twilio":        {"twilio_token"},
	"aws_sns":       {"aws_secret_key"},
	"netgsm":        {"netgsm_password"},
	"ileti_merkezi": {"iletimerkezi_secret"},
	"verimor":       {"verimor_password"},
	"turkcell":      {"turkcell_password"},
	"vodafone":      {"vodafone_secret"},
	"turk_telekom":  {"turktelekom_secret"},
	"mutlucell":     {"mutlucell_password", "mutlucell_api_key"},
	"webhook":       {"webhook_api_key"},
}

// MaskCredentials replaces sensitive credential values with MaskedValue.
func MaskCredentials(settings *DBSMSSettings) {
	if settings.Credentials == nil {
		return
	}
	fields, ok := SensitiveFields[settings.Provider]
	if !ok {
		return
	}
	for _, field := range fields {
		if val, exists := settings.Credentials[field]; exists && val != "" {
			settings.Credentials[field] = MaskedValue
		}
	}
}

// MergeCredentials merges incoming credentials with existing ones from the database.
// If a credential value equals MaskedValue, the existing DB value is preserved.
func MergeCredentials(incoming, existing *DBSMSSettings) {
	if incoming.Credentials == nil {
		incoming.Credentials = map[string]string{}
	}
	if existing == nil || existing.Credentials == nil {
		return
	}
	for key, val := range incoming.Credentials {
		if val == MaskedValue {
			if existingVal, ok := existing.Credentials[key]; ok {
				incoming.Credentials[key] = existingVal
			} else {
				delete(incoming.Credentials, key)
			}
		}
	}
}

// ValidateOTPSettings clamps OTP settings to acceptable ranges.
func ValidateOTPSettings(settings *DBSMSSettings) {
	if settings.OTPLength < 4 || settings.OTPLength > 8 {
		settings.OTPLength = 6
	}
	if settings.OTPExpiry < 60 || settings.OTPExpiry > 600 {
		settings.OTPExpiry = 300
	}
	if settings.MaxAttempts < 1 || settings.MaxAttempts > 10 {
		settings.MaxAttempts = 3
	}
}
