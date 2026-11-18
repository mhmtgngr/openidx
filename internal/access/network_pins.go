package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// WHO ANSWERS THE NAMES OF TUNNELED APPLICATIONS (migration 264).
//
// org_network_policy.name_resolution is 'tunnel' (default: the tunneler answers
// the name, as always) or 'agent'. Next to a VPN client that enforces its own
// DNS the tunneler never sees the question, so with 'agent' every network
// resource that can have one gets a pin: a stable overlay address from
// nameResolutionPool that the service ALSO intercepts. The device is told
// which names have which pin (agentNetworkPolicy.NamePins) and answers them
// itself; a dial to the pin is the same service as a dial to the name.

const (
	nameResolutionTunnel = "tunnel"
	nameResolutionAgent  = "agent"
)

// firstPinOffset keeps the first few addresses of the pool free.
const firstPinOffset = 10

// maxPinAttempts bounds the retry when two writers pick the same free address.
const maxPinAttempts = 3

// allocatePin gives the resource its pin if it has none and returns it: the
// lowest address of the pool that no resource of ANY organization holds. All
// organizations share one overlay, and the tunneler on a device keeps one
// intercept per address, so two organizations' services intercepting the same
// pin would send one's traffic to the other's backend: uniqueness is install
// wide (the index is on pin_ip alone), and so is the search, which therefore
// has to see every organization's rows (a bypass context, as the reconciler
// runs). It is stable (an existing pin is returned as it is, whatever the
// setting is now) and safe to race: the unique index refuses a second writer,
// which reads again.
func allocatePin(ctx context.Context, db *database.PostgresDB, orgID, appID string) (string, error) {
	ctx = orgctx.WithBypassRLS(ctx)
	for attempt := 0; attempt < maxPinAttempts; attempt++ {
		var pin *string
		err := db.Pool.QueryRow(ctx,
			//orgscope:ignore install-wide Ziti reconcile; the row is keyed by the application's globally-unique id and its own org_id
			`UPDATE network_targets SET pin_ip = (
			    SELECT ('100.127.0.0'::inet + n) FROM generate_series($3::int, 65534) AS n
			     WHERE NOT EXISTS (SELECT 1 FROM network_targets x
			                        WHERE x.pin_ip = ('100.127.0.0'::inet + n))
			     ORDER BY n LIMIT 1)
			  WHERE application_id = $1 AND org_id = $2 AND pin_ip IS NULL
			  RETURNING host(pin_ip)`, appID, orgID, firstPinOffset).Scan(&pin)
		var pgErr *pgconn.PgError
		switch {
		case err == nil && pin != nil:
			return *pin, nil
		case err == nil:
			return "", errors.New("the pin pool is full")
		case errors.As(err, &pgErr) && pgErr.Code == "23505":
			continue // another writer took that address; read the next free one
		case errors.Is(err, pgx.ErrNoRows):
			// Already has one (someone else allocated it first): read it.
			var existing *string
			if rerr := db.Pool.QueryRow(ctx,
				`SELECT host(pin_ip) FROM network_targets WHERE application_id = $1 AND org_id = $2`,
				appID, orgID).Scan(&existing); rerr != nil {
				return "", rerr
			}
			if existing == nil {
				return "", errors.New("the resource has no network target")
			}
			return *existing, nil
		default:
			return "", err
		}
	}
	return "", fmt.Errorf("could not allocate a pin after %d attempts", maxPinAttempts)
}

// namePin is one name the agent answers itself and the address it answers with.
// Service is the overlay service behind it: a device only answers the name while
// its tunneler lists that service among those it may dial, so a resource the
// reconciler refused (or one the device cannot dial) is never answered with an
// address that leads nowhere.
type namePin struct {
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Service string `json:"service,omitempty"`
}

// namePinsVersion is the digest of a set of pins (16 hex characters of a
// SHA-256 over the sorted pairs), "" for none. It is NOT part of the policy
// version: pins differ by device, and the console compares the organization's
// policy version with what each device reports.
func namePinsVersion(pins []namePin) string {
	if len(pins) == 0 {
		return ""
	}
	h := sha256.New()
	for _, p := range pins {
		fmt.Fprintf(h, "%s=%s=%s\n", p.Name, p.IP, p.Service)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// loadDeviceNamePins is the pins one device is told about: the pinned names of
// the organization's enabled network resources that the device can dial. With
// assignment enforcement off every enrolled device may dial every network
// service (the blanket grant), so every pin; with it on, only the resources the
// enrolling person is assigned (directly or through a group), the same rule
// the service's Dial policy states (networkDialPolicy). A name the device could
// not dial must not be answered with a pin: the device would be cut off from
// the path it reaches the name by today.
func loadDeviceNamePins(ctx context.Context, db *database.PostgresDB, orgID, agentID string, enforce bool) ([]namePin, error) {
	var assigned []string
	if enforce {
		var userID string
		if err := db.Pool.QueryRow(ctx,
			`SELECT COALESCE(enrolled_by_user_id::text, '') FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`,
			agentID, orgID).Scan(&userID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if userID == "" {
			return nil, nil
		}
		refs, err := appaccess.AppsForUser(ctx, db, userID, orgID)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			assigned = append(assigned, r.ID)
		}
		if len(assigned) == 0 {
			return nil, nil
		}
	}
	rows, err := db.Pool.Query(ctx,
		`SELECT lower(nt.dns_names[1]), host(nt.pin_ip), a.id::text
		   FROM network_targets nt
		   JOIN applications a ON a.id = nt.application_id AND a.org_id = nt.org_id
		  WHERE nt.org_id = $1 AND a.kind = 'network' AND a.enabled = true
		    AND nt.pin_ip IS NOT NULL
		    AND cardinality(nt.dns_names) = 1 AND cardinality(nt.hosts) = 0
		    AND cardinality(COALESCE(nt.cidrs::text[], '{}')) = 0
		    AND nt.dns_names[1] NOT LIKE '*%'
		    AND ($2::bool = false OR a.id::text = ANY($3))
		  ORDER BY 1`, orgID, enforce, assigned)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pins []namePin
	for rows.Next() {
		var p namePin
		var appID string
		if err := rows.Scan(&p.Name, &p.IP, &appID); err != nil {
			return nil, err
		}
		p.Service = networkServiceName(appID)
		pins = append(pins, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].Name < pins[j].Name })
	return pins, nil
}
