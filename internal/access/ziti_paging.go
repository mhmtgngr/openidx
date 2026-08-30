package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Paginating list helpers for the Ziti management API.
//
// The pre-existing ListServices/ListServicePolicies ask for `limit=1000` and
// return whatever one page holds, discarding `meta`. That is fine for the
// convergence loops that use them, but it is not fine for the assignment
// report: a silently truncated listing under-reports reach, and under-reported
// reach reads as "nobody loses anything — safe to enforce". Inferring
// truncation from `len(...) >= limit` does not close the hole either, because
// the controller is free to cap `limit` server-side below what we asked for
// (OpenZiti versions have done exactly that), in which case a truncated page
// never reaches the threshold.
//
// These helpers therefore read `meta.pagination` — which is authoritative —
// and page until every record has been fetched. A response WITHOUT
// `meta.pagination` is an unknown-completeness signal and is reported as an
// error, never assumed complete.

// zitiPagination is the `meta.pagination` block every OpenZiti management API
// list response carries. The fields are pointers so an absent block and a
// zero-valued one stay distinguishable: `totalCount: 0` is a legitimate empty
// collection, a missing `totalCount` is "we cannot tell how much there is".
type zitiPagination struct {
	Limit      *int `json:"limit"`
	Offset     *int `json:"offset"`
	TotalCount *int `json:"totalCount"`
}

// zitiListPageSize is what the paginating helpers ask for per page. The
// controller may honour less; the loop below follows what it actually returned
// rather than what it was asked for, so a server-side cap costs extra requests
// and never silently truncates.
const zitiListPageSize = 500

// zitiMaxListPages bounds the paging loop. Termination does not depend on it —
// every continuing iteration appends at least one record and advances the
// offset by that many — but a controller whose totalCount grows faster than we
// can read it would otherwise spin. Hitting the bound is an error, not a
// truncated success.
const zitiMaxListPages = 1000

// listAllPaged fetches every record of a management API collection, following
// meta.pagination. It returns an error rather than a partial list whenever
// completeness cannot be established.
func listAllPaged[T any](zm *ZitiManager, collection string) ([]T, error) {
	out := []T{}
	offset := 0
	for page := 0; ; page++ {
		if page >= zitiMaxListPages {
			return nil, fmt.Errorf("listing %s did not terminate within %d pages", collection, zitiMaxListPages)
		}
		path := fmt.Sprintf("/edge/management/v1/%s?limit=%d&offset=%d", collection, zitiListPageSize, offset)
		respData, statusCode, err := zm.mgmtRequest("GET", path, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to list %s: %w", collection, err)
		}
		if statusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d listing %s", statusCode, collection)
		}

		var resp struct {
			Data []T `json:"data"`
			Meta struct {
				Pagination *zitiPagination `json:"pagination"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(respData, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse %s response: %w", collection, err)
		}

		p := resp.Meta.Pagination
		if p == nil || p.TotalCount == nil {
			// Completeness is unknowable. Say so; do not assume this page is
			// everything, which is the failure direction that reads as "safe".
			return nil, fmt.Errorf(
				"controller response for %s carried no meta.pagination.totalCount, "+
					"so the listing cannot be shown to be complete", collection)
		}

		out = append(out, resp.Data...)
		if len(out) >= *p.TotalCount {
			return out, nil
		}
		if len(resp.Data) == 0 {
			// More records are claimed to exist but the controller returned
			// none: paging cannot make progress, so the listing is incomplete.
			return nil, fmt.Errorf(
				"controller returned an empty page of %s at offset %d while reporting totalCount %d: "+
					"the listing is incomplete", collection, offset, *p.TotalCount)
		}
		offset += len(resp.Data)
	}
}

// ListAllServicePolicies returns every service policy on the controller,
// following pagination. Unlike ListServicePolicies it never returns a
// silently-truncated list.
func (zm *ZitiManager) ListAllServicePolicies(_ context.Context) ([]ZitiServicePolicyInfo, error) {
	return listAllPaged[ZitiServicePolicyInfo](zm, "service-policies")
}

// ListAllServices returns every service on the controller, following
// pagination. Unlike ListServices it never returns a silently-truncated list.
func (zm *ZitiManager) ListAllServices(_ context.Context) ([]ZitiServiceInfo, error) {
	return listAllPaged[ZitiServiceInfo](zm, "services")
}
