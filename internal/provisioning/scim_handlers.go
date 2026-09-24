package provisioning

// The SCIM 2.0 HTTP endpoints (RFC 7644). The service functions they call --
// CreateSCIMUser, UpdateSCIMGroup and the rest -- hold the persistence; these
// hold the protocol: status codes, the error envelope, Location, and what a
// PATCH means.
//
// The failure log lines below carry the error and no resource id. The id is
// the request's path segment, which the request logger already records, and a
// caller-supplied value does not become safe to log by being cleaned. For the
// same reason the list handlers parse the filter themselves: the error they
// log comes from the query alone and never quotes the caller's filter.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	scimSchemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchemaListResp   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimMaxResults       = 200
	scimDefaultPageCount = 100
)

// scimListParams reads startIndex and count (RFC 7644 §3.4.2.4): a startIndex
// below 1 is 1, a negative count is 0, and count is capped at the maximum
// /ServiceProviderConfig advertises. A value that is not an integer is a 400,
// not silently the default.
func scimListParams(c *gin.Context) (startIndex, count int, ok bool) {
	startIndex, count = 1, scimDefaultPageCount
	if v := c.Query("startIndex"); v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "startIndex must be an integer")
			return 0, 0, false
		}
		startIndex = n
	}
	if v := c.Query("count"); v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "count must be an integer")
			return 0, 0, false
		}
		count = n
	}
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	if count > scimMaxResults {
		count = scimMaxResults
	}
	return startIndex, count, true
}

// validSCIMID reports whether id could name a resource. An id that cannot is
// a resource that does not exist: 404, as for any other unknown id.
func validSCIMID(c *gin.Context, id string) bool {
	if _, err := uuid.Parse(id); err != nil {
		scimError(c, http.StatusNotFound, "", "Resource not found")
		return false
	}
	return true
}

// decodeSCIMBody decodes a request body and reports which top-level
// attributes it named, case-insensitively, as SCIM attribute names are.
func decodeSCIMBody(c *gin.Context, into interface{}) (present map[string]bool, ok bool) {
	raw, err := c.GetRawData()
	if err == nil {
		err = json.Unmarshal(raw, into)
	}
	var probe map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(raw, &probe)
	}
	if err != nil {
		scimError(c, http.StatusBadRequest, scimTypeInvalidSyntax, "the request body is not a SCIM resource: "+err.Error())
		return nil, false
	}
	present = make(map[string]bool, len(probe))
	for k := range probe {
		present[strings.ToLower(k)] = true
	}
	return present, true
}

// --- Users ------------------------------------------------------------------

func (s *Service) handleListUsers(c *gin.Context) {
	startIndex, count, ok := scimListParams(c)
	if !ok {
		return
	}
	// The filter is parsed here, apart from the query, so a filter this server
	// cannot honour is answered 400 and its text never reaches the error that
	// is logged below.
	pred, err := parseSCIMFilter(c.Query("filter"), scimUserFilterAttrs)
	if err != nil {
		scimError(c, http.StatusBadRequest, scimTypeInvalidFilter, err.Error())
		return
	}
	resp, err := s.listSCIMUsers(c.Request.Context(), startIndex, count, pred)
	if err != nil {
		s.logger.Error("failed to list SCIM users", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to list users")
		return
	}
	if users, ok := resp.Resources.([]SCIMUser); ok {
		for i := range users {
			users[i].Meta.Location = scimResourceLocation(c, "Users", users[i].ID)
		}
	}
	c.JSON(http.StatusOK, resp)
}

// respondUser answers with the stored representation of a user -- what a GET
// returns -- rather than an echo of the request, so the client sees what was
// actually kept.
func (s *Service) respondUser(c *gin.Context, status int, id string) {
	user, err := s.GetSCIMUser(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("failed to read back a SCIM user", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to read the user")
		return
	}
	user.Meta.Location = scimResourceLocation(c, "Users", id)
	if status == http.StatusCreated {
		c.Header("Location", user.Meta.Location)
	}
	c.JSON(status, user)
}

func validateSCIMUser(c *gin.Context, user *SCIMUser) bool {
	if strings.TrimSpace(user.UserName) == "" {
		scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "userName is required")
		return false
	}
	if len(user.UserName) > 255 {
		scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "userName too long")
		return false
	}
	for _, email := range user.Emails {
		if len(email.Value) > 254 {
			scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "Email exceeds maximum length of 254 characters")
			return false
		}
	}
	return true
}

func (s *Service) handleCreateUser(c *gin.Context) {
	var user SCIMUser
	present, ok := decodeSCIMBody(c, &user)
	if !ok || !validateSCIMUser(c, &user) {
		return
	}
	// active is optional (RFC 7643 §4.1.1); a client that leaves it out is
	// provisioning an account it expects to be usable.
	if !present["active"] {
		user.Active = true
	}

	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	created, err := s.CreateSCIMUser(ctx, &user)
	if err != nil {
		if isUniqueViolation(err) {
			scimError(c, http.StatusConflict, scimTypeUniqueness, "userName or email is already in use")
			return
		}
		s.logger.Error("failed to create SCIM user", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to create user")
		return
	}
	s.respondUser(c, http.StatusCreated, created.ID)
}

func (s *Service) handleGetUser(c *gin.Context) {
	id := c.Param("id")
	if !validSCIMID(c, id) {
		return
	}
	user, err := s.GetSCIMUser(c.Request.Context(), id)
	if err != nil {
		if isNotFound(err) {
			scimError(c, http.StatusNotFound, "", "User not found")
			return
		}
		s.logger.Error("failed to get SCIM user", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to get user")
		return
	}
	user.Meta.Location = scimResourceLocation(c, "Users", id)
	c.JSON(http.StatusOK, user)
}

// existingUser loads the user a PUT, PATCH or DELETE names, answering 404
// itself when there is none.
func (s *Service) existingUser(c *gin.Context, id string) (*SCIMUser, bool) {
	if !validSCIMID(c, id) {
		return nil, false
	}
	user, err := s.GetSCIMUser(c.Request.Context(), id)
	if err != nil {
		if isNotFound(err) {
			scimError(c, http.StatusNotFound, "", "User not found")
			return nil, false
		}
		s.logger.Error("failed to get SCIM user", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to get user")
		return nil, false
	}
	return user, true
}

func (s *Service) updateAndRespondUser(c *gin.Context, id string, user *SCIMUser) {
	if _, err := s.UpdateSCIMUser(c.Request.Context(), id, user); err != nil {
		if isUniqueViolation(err) {
			scimError(c, http.StatusConflict, scimTypeUniqueness, "userName or email is already in use")
			return
		}
		s.logger.Error("failed to update SCIM user", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to update user")
		return
	}
	s.respondUser(c, http.StatusOK, id)
}

func (s *Service) handleReplaceUser(c *gin.Context) {
	id := c.Param("id")
	existing, ok := s.existingUser(c, id)
	if !ok {
		return
	}
	var user SCIMUser
	present, ok := decodeSCIMBody(c, &user)
	if !ok || !validateSCIMUser(c, &user) {
		return
	}
	// A PUT that does not mention active keeps it as it is: re-enabling a
	// disabled account is not something a client may do by omission.
	if !present["active"] {
		user.Active = existing.Active
	}
	s.updateAndRespondUser(c, id, &user)
}

func (s *Service) handlePatchUser(c *gin.Context) {
	id := c.Param("id")
	user, ok := s.existingUser(c, id)
	if !ok {
		return
	}
	var patch SCIMPatchRequest
	if _, ok := decodeSCIMBody(c, &patch); !ok {
		return
	}
	if len(patch.Operations) == 0 {
		scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "a PATCH request must carry at least one operation")
		return
	}
	for _, op := range patch.Operations {
		if err := s.applyUserPatchOperation(user, op); err != nil {
			writePatchError(c, err)
			return
		}
	}
	if !validateSCIMUser(c, user) {
		return
	}
	s.updateAndRespondUser(c, id, user)
}

func (s *Service) handleDeleteUser(c *gin.Context) {
	id := c.Param("id")
	if _, ok := s.existingUser(c, id); !ok {
		return
	}
	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	if err := s.DeleteSCIMUser(ctx, id); err != nil {
		s.logger.Error("failed to delete SCIM user", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to delete user")
		return
	}
	scimNoContent(c)
}

// emailValueByType matches emails[type eq "work"].value, the path Microsoft
// Entra writes a user's email with.
var emailValueByType = regexp.MustCompile(`(?i)^\s*emails\s*\[\s*type\s+eq\s+"([^"]+)"\s*\]\s*\.\s*value\s*$`)

// applyUserPatchOperation applies one PATCH operation (RFC 7644 §3.5.2) to a
// user. A path this server does not model is an error (400 invalidPath), not
// a silent success: answering 200 to a change that was not made tells the
// client its directory and this one agree when they do not.
func (s *Service) applyUserPatchOperation(user *SCIMUser, op SCIMPatchOperation) error {
	kind, err := scimOp(op.Op)
	if err != nil {
		return err
	}
	path := strings.TrimSpace(op.Path)
	if path == "" {
		// No path: the value is a set of attributes of the resource itself
		// (§3.5.2.1, §3.5.2.3). A remove needs a target (§3.5.2.2).
		if kind == "remove" {
			return &patchError{scimType: scimTypeNoTarget, msg: "a remove operation needs a path"}
		}
		attrs, ok := op.Value.(map[string]interface{})
		if !ok {
			return invalidValue("an operation without a path must carry an object of attributes")
		}
		for name, value := range attrs {
			if err := s.applyUserPatchOperation(user, SCIMPatchOperation{Op: kind, Path: name, Value: value}); err != nil {
				return err
			}
		}
		return nil
	}

	if m := emailValueByType.FindStringSubmatch(path); m != nil {
		return applyEmailByType(user, kind, m[1], op.Value)
	}

	setString := func(target *string, attr string) error {
		if kind == "remove" {
			*target = ""
			return nil
		}
		v, ok := scimString(op.Value)
		if !ok {
			return invalidValue("%s must be a string", attr)
		}
		*target = v
		return nil
	}

	switch strings.ToLower(path) {
	case "active":
		if kind == "remove" {
			return invalidValue("active cannot be removed")
		}
		v, ok := scimBool(op.Value)
		if !ok {
			return invalidValue("active must be a boolean")
		}
		user.Active = v
	case "username":
		if kind == "remove" {
			return invalidValue("userName is required and cannot be removed")
		}
		return setString(&user.UserName, "userName")
	case "displayname":
		return setString(&user.DisplayName, "displayName")
	case "externalid":
		return setString(&user.ExternalID, "externalId")
	case "name.givenname":
		return setString(&user.Name.GivenName, "name.givenName")
	case "name.familyname":
		return setString(&user.Name.FamilyName, "name.familyName")
	case "name":
		if kind == "remove" {
			user.Name = SCIMName{}
			return nil
		}
		parts, ok := op.Value.(map[string]interface{})
		if !ok {
			return invalidValue("name must be an object")
		}
		for sub, v := range parts {
			if err := s.applyUserPatchOperation(user, SCIMPatchOperation{Op: kind, Path: "name." + sub, Value: v}); err != nil {
				return err
			}
		}
	case "emails":
		switch kind {
		case "replace":
			// Replace the whole emails collection with the supplied set.
			user.Emails = parseSCIMEmails(op.Value)
		case "add":
			// SCIM `add` on a multi-valued attribute unions the supplied values
			// into the existing collection (RFC 7644 §3.5.2.1).
			user.Emails = mergeSCIMEmails(user.Emails, parseSCIMEmails(op.Value))
		case "remove":
			// SCIM `remove` with no value clears the targeted collection; with a
			// value it removes the matching members (RFC 7644 §3.5.2.2).
			if op.Value == nil {
				user.Emails = nil
			} else {
				user.Emails = removeSCIMEmails(user.Emails, parseSCIMEmails(op.Value))
			}
		}
	default:
		return invalidPath(path)
	}
	return nil
}

// applyEmailByType sets or clears the email of one type.
func applyEmailByType(user *SCIMUser, kind, emailType string, value interface{}) error {
	kept := make([]SCIMEmail, 0, len(user.Emails))
	for _, e := range user.Emails {
		if !strings.EqualFold(e.Type, emailType) {
			kept = append(kept, e)
		}
	}
	if kind == "remove" {
		user.Emails = kept
		return nil
	}
	v, ok := scimString(value)
	if !ok || v == "" {
		return invalidValue("emails[type eq %q].value must be a non-empty string", emailType)
	}
	user.Emails = append([]SCIMEmail{{Value: v, Type: emailType, Primary: true}}, kept...)
	for i := 1; i < len(user.Emails); i++ {
		user.Emails[i].Primary = false
	}
	return nil
}

// parseSCIMEmails coerces a SCIM PATCH value into a slice of SCIMEmail. The
// value may be a single email object or an array of them; entries without a
// usable "value" are dropped.
func parseSCIMEmails(value interface{}) []SCIMEmail {
	toEmail := func(m map[string]interface{}) (SCIMEmail, bool) {
		addr, ok := m["value"].(string)
		if !ok || addr == "" {
			return SCIMEmail{}, false
		}
		email := SCIMEmail{Value: addr}
		if t, ok := m["type"].(string); ok {
			email.Type = t
		}
		if p, ok := m["primary"].(bool); ok {
			email.Primary = p
		}
		return email, true
	}

	var emails []SCIMEmail
	switch v := value.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if email, ok := toEmail(m); ok {
					emails = append(emails, email)
				}
			}
		}
	case map[string]interface{}:
		if email, ok := toEmail(v); ok {
			emails = append(emails, email)
		}
	case string:
		// Bare string form: PATCH path was "emails.value".
		if v != "" {
			emails = append(emails, SCIMEmail{Value: v})
		}
	}
	return emails
}

// mergeSCIMEmails unions incoming emails into existing ones, deduping by
// address (case-insensitive). When an incoming email is marked primary it
// becomes the sole primary, matching SCIM's single-primary invariant.
func mergeSCIMEmails(existing, incoming []SCIMEmail) []SCIMEmail {
	index := make(map[string]int, len(existing))
	merged := make([]SCIMEmail, len(existing))
	copy(merged, existing)
	for i, e := range merged {
		index[strings.ToLower(e.Value)] = i
	}
	for _, in := range incoming {
		if in.Primary {
			for i := range merged {
				merged[i].Primary = false
			}
		}
		if pos, ok := index[strings.ToLower(in.Value)]; ok {
			merged[pos] = in
			continue
		}
		index[strings.ToLower(in.Value)] = len(merged)
		merged = append(merged, in)
	}
	return merged
}

// removeSCIMEmails drops any existing email whose address matches one of the
// supplied emails (case-insensitive).
func removeSCIMEmails(existing, toRemove []SCIMEmail) []SCIMEmail {
	drop := make(map[string]struct{}, len(toRemove))
	for _, e := range toRemove {
		drop[strings.ToLower(e.Value)] = struct{}{}
	}
	kept := make([]SCIMEmail, 0, len(existing))
	for _, e := range existing {
		if _, ok := drop[strings.ToLower(e.Value)]; ok {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// --- Groups -----------------------------------------------------------------

// applyGroupPatchOperation applies one PATCH operation to a group. Members
// are added, removed (all, the listed values, or the one a
// members[value eq "id"] filter names) or replaced wholesale.
func (s *Service) applyGroupPatchOperation(group *SCIMGroup, op SCIMPatchOperation) error {
	kind, err := scimOp(op.Op)
	if err != nil {
		return err
	}
	path := strings.TrimSpace(op.Path)
	if path == "" {
		if kind == "remove" {
			return &patchError{scimType: scimTypeNoTarget, msg: "a remove operation needs a path"}
		}
		attrs, ok := op.Value.(map[string]interface{})
		if !ok {
			return invalidValue("an operation without a path must carry an object of attributes")
		}
		for name, value := range attrs {
			if err := s.applyGroupPatchOperation(group, SCIMPatchOperation{Op: kind, Path: name, Value: value}); err != nil {
				return err
			}
		}
		return nil
	}

	if m := memberFilterPath.FindStringSubmatch(path); m != nil {
		if kind != "remove" {
			return invalidPath(path)
		}
		group.Members = withoutMembers(group.Members, map[string]struct{}{m[1]: {}})
		return nil
	}

	switch strings.ToLower(path) {
	case "displayname":
		if kind == "remove" {
			return invalidValue("displayName is required and cannot be removed")
		}
		v, ok := scimString(op.Value)
		if !ok || strings.TrimSpace(v) == "" {
			return invalidValue("displayName must be a non-empty string")
		}
		group.DisplayName = v
	case "externalid":
		if kind == "remove" {
			group.ExternalID = ""
			return nil
		}
		v, ok := scimString(op.Value)
		if !ok {
			return invalidValue("externalId must be a string")
		}
		group.ExternalID = v
	case "members":
		switch kind {
		case "add":
			// Union the supplied members into the group, deduping by user id.
			existing := make(map[string]struct{}, len(group.Members))
			for _, m := range group.Members {
				existing[m.Value] = struct{}{}
			}
			for _, value := range parseSCIMMemberValues(op.Value) {
				if _, ok := existing[value]; ok {
					continue
				}
				existing[value] = struct{}{}
				group.Members = append(group.Members, SCIMMember{Value: value, Type: "User"})
			}
		case "replace":
			group.Members = []SCIMMember{}
			for _, value := range parseSCIMMemberValues(op.Value) {
				group.Members = append(group.Members, SCIMMember{Value: value, Type: "User"})
			}
		case "remove":
			// A remove with no value clears every member; with a value it drops
			// the matching ones. Either way the result must be a non-nil slice
			// so UpdateSCIMGroup persists the (possibly empty) membership set —
			// a nil slice is treated as "members not supplied" and skipped,
			// which previously made removing the last member a silent no-op.
			if op.Value == nil {
				group.Members = []SCIMMember{}
				return nil
			}
			drop := make(map[string]struct{})
			for _, value := range parseSCIMMemberValues(op.Value) {
				drop[value] = struct{}{}
			}
			group.Members = withoutMembers(group.Members, drop)
		}
	default:
		return invalidPath(path)
	}
	return nil
}

// withoutMembers returns members minus those in drop, never nil.
func withoutMembers(members []SCIMMember, drop map[string]struct{}) []SCIMMember {
	kept := make([]SCIMMember, 0, len(members))
	for _, m := range members {
		if _, ok := drop[m.Value]; ok {
			continue
		}
		kept = append(kept, m)
	}
	return kept
}

// parseSCIMMemberValues extracts member user ids from a SCIM PATCH value, which
// may be an array of member objects or a single member object.
func parseSCIMMemberValues(value interface{}) []string {
	var values []string
	appendFromMap := func(m map[string]interface{}) {
		if v, ok := m["value"].(string); ok && v != "" {
			values = append(values, v)
		}
	}
	switch v := value.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				appendFromMap(m)
			}
		}
	case map[string]interface{}:
		appendFromMap(v)
	}
	return values
}

func (s *Service) handleListGroups(c *gin.Context) {
	startIndex, count, ok := scimListParams(c)
	if !ok {
		return
	}
	withMembers := true
	for _, attr := range strings.Split(c.Query("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(attr), "members") {
			withMembers = false
		}
	}
	// Parsed apart from the query, as in handleListUsers.
	pred, err := parseSCIMFilter(c.Query("filter"), scimGroupFilterAttrs)
	if err != nil {
		scimError(c, http.StatusBadRequest, scimTypeInvalidFilter, err.Error())
		return
	}
	resp, err := s.listSCIMGroups(c.Request.Context(), startIndex, count, pred, withMembers)
	if err != nil {
		s.logger.Error("failed to list SCIM groups", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to list groups")
		return
	}
	if groups, ok := resp.Resources.([]SCIMGroup); ok {
		for i := range groups {
			groups[i].Meta.Location = scimResourceLocation(c, "Groups", groups[i].ID)
		}
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Service) respondGroup(c *gin.Context, status int, id string) {
	group, err := s.GetSCIMGroup(c.Request.Context(), id)
	if err != nil {
		s.logger.Error("failed to read back a SCIM group", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to read the group")
		return
	}
	group.Meta.Location = scimResourceLocation(c, "Groups", id)
	if status == http.StatusCreated {
		c.Header("Location", group.Meta.Location)
	}
	c.JSON(status, group)
}

func validateSCIMGroup(c *gin.Context, group *SCIMGroup) bool {
	if strings.TrimSpace(group.DisplayName) == "" {
		scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "displayName is required")
		return false
	}
	return true
}

func (s *Service) handleCreateGroup(c *gin.Context) {
	var group SCIMGroup
	if _, ok := decodeSCIMBody(c, &group); !ok || !validateSCIMGroup(c, &group) {
		return
	}
	created, err := s.CreateSCIMGroup(c.Request.Context(), &group)
	if err != nil {
		if isUniqueViolation(err) {
			scimError(c, http.StatusConflict, scimTypeUniqueness, "a group with this displayName already exists")
			return
		}
		s.logger.Error("failed to create SCIM group", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to create group")
		return
	}
	s.respondGroup(c, http.StatusCreated, created.ID)
}

// existingGroup loads the group a request names, answering 404 itself when
// there is none.
func (s *Service) existingGroup(c *gin.Context, id string) (*SCIMGroup, bool) {
	if !validSCIMID(c, id) {
		return nil, false
	}
	group, err := s.GetSCIMGroup(c.Request.Context(), id)
	if err != nil {
		if isNotFound(err) {
			scimError(c, http.StatusNotFound, "", "Group not found")
			return nil, false
		}
		s.logger.Error("failed to get SCIM group", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to get group")
		return nil, false
	}
	return group, true
}

func (s *Service) handleGetGroup(c *gin.Context) {
	id := c.Param("id")
	group, ok := s.existingGroup(c, id)
	if !ok {
		return
	}
	group.Meta.Location = scimResourceLocation(c, "Groups", id)
	c.JSON(http.StatusOK, group)
}

func (s *Service) updateAndRespondGroup(c *gin.Context, id string, group *SCIMGroup) {
	if _, err := s.UpdateSCIMGroup(c.Request.Context(), id, group); err != nil {
		if isUniqueViolation(err) {
			scimError(c, http.StatusConflict, scimTypeUniqueness, "a group with this displayName already exists")
			return
		}
		s.logger.Error("failed to update SCIM group", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to update group")
		return
	}
	s.respondGroup(c, http.StatusOK, id)
}

func (s *Service) handleReplaceGroup(c *gin.Context) {
	id := c.Param("id")
	if _, ok := s.existingGroup(c, id); !ok {
		return
	}
	var group SCIMGroup
	if _, ok := decodeSCIMBody(c, &group); !ok || !validateSCIMGroup(c, &group) {
		return
	}
	// PUT replaces the resource (RFC 7644 §3.5.1): a representation without
	// members is a group without members, not "leave them as they are".
	if group.Members == nil {
		group.Members = []SCIMMember{}
	}
	s.updateAndRespondGroup(c, id, &group)
}

func (s *Service) handlePatchGroup(c *gin.Context) {
	id := c.Param("id")
	group, ok := s.existingGroup(c, id)
	if !ok {
		return
	}
	var patch SCIMPatchRequest
	if _, ok := decodeSCIMBody(c, &patch); !ok {
		return
	}
	if len(patch.Operations) == 0 {
		scimError(c, http.StatusBadRequest, scimTypeInvalidValue, "a PATCH request must carry at least one operation")
		return
	}
	// The members read back are the current set; only a membership operation
	// should rewrite them, so start from nil and let the operations say.
	current := group.Members
	group.Members = nil
	touched := false
	for _, op := range patch.Operations {
		if isMembersPath(op.Path) || opValueNamesMembers(op) {
			if !touched {
				group.Members = append([]SCIMMember{}, current...)
				touched = true
			}
		}
		if err := s.applyGroupPatchOperation(group, op); err != nil {
			writePatchError(c, err)
			return
		}
	}
	s.updateAndRespondGroup(c, id, group)
}

func isMembersPath(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	return p == "members" || memberFilterPath.MatchString(path)
}

func opValueNamesMembers(op SCIMPatchOperation) bool {
	if strings.TrimSpace(op.Path) != "" {
		return false
	}
	attrs, ok := op.Value.(map[string]interface{})
	if !ok {
		return false
	}
	for k := range attrs {
		if strings.EqualFold(k, "members") {
			return true
		}
	}
	return false
}

func (s *Service) handleDeleteGroup(c *gin.Context) {
	id := c.Param("id")
	if _, ok := s.existingGroup(c, id); !ok {
		return
	}
	ctx := ContextWithActorID(c.Request.Context(), c.GetString("user_id"))
	if err := s.DeleteSCIMGroup(ctx, id); err != nil {
		s.logger.Error("failed to delete SCIM group", zap.Error(err))
		scimError(c, http.StatusInternalServerError, "", "Failed to delete group")
		return
	}
	scimNoContent(c)
}

// --- Discovery (RFC 7644 §4) ------------------------------------------------

var scimUserSchemaAttributes = []gin.H{
	{"name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
	{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
	{"name": "name", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": []gin.H{
		{"name": "givenName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
		{"name": "familyName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
	}},
	{"name": "displayName", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
	{"name": "emails", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": []gin.H{
		{"name": "value", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
		{"name": "type", "type": "string", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
		{"name": "primary", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
	}},
	{"name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default"},
}

var scimGroupSchemaAttributes = []gin.H{
	{"name": "displayName", "type": "string", "multiValued": false, "required": true, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
	{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default"},
	{"name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": []gin.H{
		{"name": "value", "type": "string", "multiValued": false, "required": false, "mutability": "immutable", "returned": "default"},
		{"name": "display", "type": "string", "multiValued": false, "required": false, "mutability": "readOnly", "returned": "default"},
		{"name": "type", "type": "string", "multiValued": false, "required": false, "mutability": "immutable", "returned": "default"},
	}},
}

func (s *Service) scimSchema(c *gin.Context, id string) (gin.H, bool) {
	var name, description string
	var attrs []gin.H
	switch id {
	case scimSchemaUser:
		name, description, attrs = "User", "User Account", scimUserSchemaAttributes
	case scimSchemaGroup:
		name, description, attrs = "Group", "Group", scimGroupSchemaAttributes
	default:
		return nil, false
	}
	return gin.H{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"id":          id,
		"name":        name,
		"description": description,
		"attributes":  attrs,
		"meta": gin.H{
			"resourceType": "Schema",
			"location":     scimResourceLocation(c, "Schemas", id),
		},
	}, true
}

func (s *Service) handleGetSchemas(c *gin.Context) {
	var schemas []gin.H
	for _, id := range []string{scimSchemaUser, scimSchemaGroup} {
		schema, _ := s.scimSchema(c, id)
		schemas = append(schemas, schema)
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{scimSchemaListResp},
		"totalResults": len(schemas),
		"startIndex":   1,
		"itemsPerPage": len(schemas),
		"Resources":    schemas,
	})
}

func (s *Service) handleGetSchema(c *gin.Context) {
	schema, ok := s.scimSchema(c, c.Param("id"))
	if !ok {
		scimError(c, http.StatusNotFound, "", "Schema not found")
		return
	}
	c.JSON(http.StatusOK, schema)
}

func (s *Service) scimResourceType(c *gin.Context, id string) (gin.H, bool) {
	rt := gin.H{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":      id,
		"name":    id,
		"meta": gin.H{
			"resourceType": "ResourceType",
			"location":     scimResourceLocation(c, "ResourceTypes", id),
		},
	}
	switch id {
	case "User":
		rt["endpoint"] = "/Users"
		rt["description"] = "User Account"
		rt["schema"] = scimSchemaUser
		rt["schemaExtensions"] = []gin.H{{"schema": scimEnterpriseUserSchema, "required": false}}
	case "Group":
		rt["endpoint"] = "/Groups"
		rt["description"] = "Group"
		rt["schema"] = scimSchemaGroup
	default:
		return nil, false
	}
	return rt, true
}

// handleGetResourceTypes answers a ListResponse of ResourceType resources
// (RFC 7644 §4, RFC 7643 §6). It used to answer a bare JSON array, which no
// SCIM client's discovery reads.
func (s *Service) handleGetResourceTypes(c *gin.Context) {
	var types []gin.H
	for _, id := range []string{"User", "Group"} {
		rt, _ := s.scimResourceType(c, id)
		types = append(types, rt)
	}
	c.JSON(http.StatusOK, gin.H{
		"schemas":      []string{scimSchemaListResp},
		"totalResults": len(types),
		"startIndex":   1,
		"itemsPerPage": len(types),
		"Resources":    types,
	})
}

func (s *Service) handleGetResourceType(c *gin.Context) {
	rt, ok := s.scimResourceType(c, c.Param("id"))
	if !ok {
		scimError(c, http.StatusNotFound, "", "Resource type not found")
		return
	}
	c.JSON(http.StatusOK, rt)
}

// handleGetServiceProviderConfig says what this server supports (RFC 7643
// §5), and only that. changePassword and sort used to be advertised as
// supported, although no password attribute is read and sortBy is ignored.
func (s *Service) handleGetServiceProviderConfig(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://docs.openidx.io/scim",
		"patch":            gin.H{"supported": true},
		"bulk":             gin.H{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           gin.H{"supported": true, "maxResults": scimMaxResults},
		"changePassword":   gin.H{"supported": false},
		"sort":             gin.H{"supported": false},
		"etag":             gin.H{"supported": false},
		"authenticationSchemes": []gin.H{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "An OAuth 2.0 bearer token issued by the OpenIDX authorization server",
			"primary":     true,
		}},
		"meta": gin.H{
			"resourceType": "ServiceProviderConfig",
			"location":     strings.TrimSuffix(scimResourceLocation(c, "ServiceProviderConfig", ""), "/"),
		},
	})
}
