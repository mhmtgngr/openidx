package access

import "testing"

// A network_service request's attribute, jit-<request-id>, opens the dial only
// through the Dial policy OpenIDX writes for that request. An organization's
// administrator may neither put it on an identity, nor take it off one, nor
// name it in a policy of their own: any of the three would open or close a
// dial the request did not decide. Another attribute stays theirs to manage.
func TestAJITAttributeIsOpenIDXs(t *testing.T) {
	const org = "00000000-0000-0000-0000-0000000000aa"
	f := &zitiFabric{orgID: org, serviceOrg: map[string]string{}, identityOrg: map[string]string{}, policyOrg: map[string]string{}}
	jit := "jit-6f1c2a54-3a3e-4f43-9a52-0c8f3ac2b7d1"

	if err := f.checkIdentityAttributes([]string{"ops"}, []string{"ops", jit}); err == nil {
		t.Error("an administrator added a request's jit- attribute to an identity")
	}
	if err := f.checkIdentityAttributes([]string{"ops", jit}, []string{"ops"}); err == nil {
		t.Error("an administrator took a request's jit- attribute off an identity")
	}
	if err := f.checkIdentityRoles([]string{"#" + jit}); err == nil {
		t.Error("an administrator named a request's jit- attribute in a policy of their own")
	}

	if err := f.checkIdentityAttributes([]string{"ops"}, []string{"ops", "release-crew"}); err != nil {
		t.Errorf("an administrator could not add an attribute of their own: %v", err)
	}
	if err := f.checkIdentityRoles([]string{"#release-crew"}); err != nil {
		t.Errorf("an administrator could not name an attribute of their own: %v", err)
	}
}
