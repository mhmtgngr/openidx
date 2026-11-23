package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// errAmbiguousLoginIdentifier is what resolveLoginUser answers when what was
// typed names more than one account at the same level of the lookup (a shared
// mailbox on two accounts, two usernames that differ only in case). The sign-in
// refuses it with the same generic error as an unknown name.
var errAmbiguousLoginIdentifier = errors.New("the sign-in identifier names more than one account")

// resolveLoginUser finds the account a typed sign-in identifier names, within
// the organization, and returns its id and its STORED username.
//
// The login page says "Username or Email" and people type what they know: the
// account name, the address their mail client uses, in whatever case and with
// whatever autofill whitespace. The lookup is therefore layered, and the first
// layer that finds anything decides:
//
//  0. the username, exactly as typed (what sign-in has always done, so a pair
//     of usernames that differ only in case still sign in as themselves);
//  1. the username, ignoring case;
//  2. an ADDRESS, ignoring case: users.email (for a directory user whatever the
//     attribute mapping puts there, often the UPN), users.mail (the
//     directory's mail attribute, the address a person actually uses, kept as a
//     second sign-in address, migration 265) or an address an administrator
//     gave the account (user_login_addresses, migration 266: the directory sync
//     rewrites users.mail every run, so a hand-given address needs a home the
//     sync does not own, and a local account has no directory at all).
//
// The order is the safety property: an account's name always beats anyone's
// address, so an address cannot take over another account's username. The three
// kinds of address share ONE layer, on purpose: if one account's email is
// another account's mail (an unverified or locally provisioned email that
// happens to be a directory person's mailbox), neither is preferred, so the
// address signs in as neither and the refusal is audited, instead of one of
// them silently capturing the other's address. One account is one hit (an
// account whose email and mail are the same address is a single row). One hit
// in a layer is the account; two hits in the same layer is
// errAmbiguousLoginIdentifier, never a pick. An unknown identifier is
// ErrInvalidCredentials.
func (s *Service) resolveLoginUser(ctx context.Context, orgID, identifier string) (id, username string, err error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "", "", ErrInvalidCredentials
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT id::text, username, tier FROM (
			SELECT id, username, 0 AS tier FROM users WHERE org_id = $2 AND username = $1
			UNION ALL
			SELECT id, username, 1 FROM users WHERE org_id = $2 AND lower(username) = lower($1)
			UNION ALL
			SELECT id, username, 2 FROM users WHERE org_id = $2
			   AND (lower(email) = lower($1) OR (mail IS NOT NULL AND lower(mail) = lower($1))
			        OR id IN (SELECT user_id FROM user_login_addresses WHERE org_id = $2 AND address = lower($1)))
		) m
		ORDER BY tier, username
		LIMIT 2`, identifier, orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrInvalidCredentials
		}
		return "", "", err
	}
	defer rows.Close()

	type hit struct {
		id, username string
		tier         int
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.id, &h.username, &h.tier); err != nil {
			return "", "", err
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	switch {
	case len(hits) == 0:
		return "", "", ErrInvalidCredentials
	case len(hits) == 2 && hits[0].tier == hits[1].tier:
		s.logger.Warn("sign-in identifier names more than one account",
			zap.String("identifier", logsafe.Clean(identifier)), zap.Int("layer", hits[0].tier))
		return "", "", errAmbiguousLoginIdentifier
	}
	return hits[0].id, hits[0].username, nil
}

// FindUserByLoginIdentifier is the account a typed sign-in identifier names
// (username, email or the directory's mail address, as resolveLoginUser reads
// them), for the sign-in paths that look the person up before any credential:
// passwordless phone sign-in asks for the identifier first and a push goes to
// that person's phone. An unknown or ambiguous identifier is
// ErrInvalidCredentials, which the caller answers as generically as it answers
// an unknown name.
func (s *Service) FindUserByLoginIdentifier(ctx context.Context, identifier string) (*User, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	id, _, err := s.resolveLoginUser(ctx, org.ID, identifier)
	if err != nil {
		if errors.Is(err, errAmbiguousLoginIdentifier) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	return s.GetUser(ctx, id)
}
