package directory

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// LDAPConnector manages LDAP connections and searches
type LDAPConnector struct {
	cfg    LDAPConfig
	logger *zap.Logger
}

// NewLDAPConnector creates a new LDAP connector
func NewLDAPConnector(cfg LDAPConfig, logger *zap.Logger) *LDAPConnector {
	return &LDAPConnector{
		cfg:    cfg,
		logger: logger.With(zap.String("component", "ldap-connector")),
	}
}

// Connect establishes an LDAP connection with TLS/StartTLS and binds
func (c *LDAPConnector) Connect() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.cfg.SkipTLSVerify,
		ServerName:         c.cfg.Host,
	}

	var conn *ldap.Conn
	var err error

	if c.cfg.UseTLS {
		conn, err = ldap.DialTLS("tcp", addr, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", addr, err)
	}

	if c.cfg.StartTLS && !c.cfg.UseTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS failed: %w", err)
		}
	}

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP bind failed: %w", err)
	}

	return conn, nil
}

// TestConnection verifies LDAP connectivity, bind, and a simple search
func (c *LDAPConnector) TestConnection() error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	baseDN := c.cfg.BaseDN
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("test search failed: %w", err)
	}

	c.logger.Info("LDAP connection test successful", zap.String("host", c.cfg.Host))
	return nil
}

// SearchUsers performs a paged search for user entries
func (c *LDAPConnector) SearchUsers(conn *ldap.Conn) ([]*ldap.Entry, error) {
	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	filter := c.cfg.UserFilter
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}

	attrs := c.userAttributes()
	pageSize := c.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	return c.pagedSearch(conn, baseDN, filter, attrs, pageSize)
}

// SearchGroups performs a paged search for group entries
func (c *LDAPConnector) SearchGroups(conn *ldap.Conn) ([]*ldap.Entry, error) {
	baseDN := c.cfg.GroupBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	filter := c.cfg.GroupFilter
	if filter == "" {
		filter = "(objectClass=groupOfNames)"
	}

	memberAttr := c.cfg.MemberAttribute
	if memberAttr == "" {
		memberAttr = "member"
	}

	attrs := []string{"dn", "cn", "description", memberAttr}
	if c.cfg.AttributeMapping.GroupName != "" {
		attrs = append(attrs, c.cfg.AttributeMapping.GroupName)
	}

	pageSize := c.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	return c.pagedSearch(conn, baseDN, filter, attrs, pageSize)
}

// SearchUsersIncremental searches for users modified since a given marker
func (c *LDAPConnector) SearchUsersIncremental(conn *ldap.Conn, sinceUSN int64, sinceTimestamp string) ([]*ldap.Entry, error) {
	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	baseFilter := c.cfg.UserFilter
	if baseFilter == "" {
		baseFilter = "(objectClass=inetOrgPerson)"
	}

	var filter string
	if sinceUSN > 0 {
		// Active Directory incremental sync
		filter = fmt.Sprintf("(&%s(uSNChanged>=%d))", baseFilter, sinceUSN)
	} else if sinceTimestamp != "" {
		// OpenLDAP incremental sync
		filter = fmt.Sprintf("(&%s(modifyTimestamp>=%s))", baseFilter, sinceTimestamp)
	} else {
		filter = baseFilter
	}

	attrs := c.userAttributes()
	// Add tracking attributes for incremental sync
	attrs = append(attrs, "uSNChanged", "modifyTimestamp")

	pageSize := c.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	return c.pagedSearch(conn, baseDN, filter, attrs, pageSize)
}

// AuthenticateUser binds as the user to verify credentials
func (c *LDAPConnector) AuthenticateUser(username, password string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	usernameAttr := c.cfg.AttributeMapping.Username
	if usernameAttr == "" {
		usernameAttr = "uid"
	}

	filter := fmt.Sprintf("(&%s(%s=%s))",
		c.cfg.UserFilter,
		ldap.EscapeFilter(usernameAttr),
		ldap.EscapeFilter(username),
	)
	if c.cfg.UserFilter == "" {
		filter = fmt.Sprintf("(&(objectClass=inetOrgPerson)(%s=%s))",
			ldap.EscapeFilter(usernameAttr),
			ldap.EscapeFilter(username),
		)
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("user search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return fmt.Errorf("user not found in LDAP")
	}

	userDN := result.Entries[0].DN

	// Bind as the user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return fmt.Errorf("LDAP authentication failed: %w", err)
	}

	return nil
}

// userAttributes returns the list of LDAP attributes to fetch for users
func (c *LDAPConnector) userAttributes() []string {
	m := c.cfg.AttributeMapping
	attrs := []string{"dn"}

	add := func(a string) {
		if a != "" {
			attrs = append(attrs, a)
		}
	}

	add(m.Username)
	add(m.Email)
	add(m.FirstName)
	add(m.LastName)
	add(m.DisplayName)

	// Ensure we have sensible defaults
	if m.Username == "" {
		attrs = append(attrs, "uid")
	}
	if m.Email == "" {
		attrs = append(attrs, "mail")
	}
	if m.FirstName == "" {
		attrs = append(attrs, "givenName")
	}
	if m.LastName == "" {
		attrs = append(attrs, "sn")
	}
	if m.DisplayName == "" {
		attrs = append(attrs, "cn")
	}

	return attrs
}

// pagedSearch performs a paged LDAP search
func (c *LDAPConnector) pagedSearch(conn *ldap.Conn, baseDN, filter string, attrs []string, pageSize int) ([]*ldap.Entry, error) {
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attrs,
		[]ldap.Control{ldap.NewControlPaging(uint32(pageSize))},
	)

	var allEntries []*ldap.Entry

	for {
		result, err := conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %w", err)
		}

		allEntries = append(allEntries, result.Entries...)

		pagingControl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingControl == nil {
			break
		}

		paging, ok := pagingControl.(*ldap.ControlPaging)
		if !ok || len(paging.Cookie) == 0 {
			break
		}

		// Set the cookie for next page
		searchReq.Controls = []ldap.Control{ldap.NewControlPaging(uint32(pageSize))}
		searchReq.Controls[0].(*ldap.ControlPaging).SetCookie(paging.Cookie)
	}

	c.logger.Debug("LDAP search completed",
		zap.String("baseDN", baseDN),
		zap.String("filter", filter),
		zap.Int("results", len(allEntries)),
	)

	return allEntries, nil
}
