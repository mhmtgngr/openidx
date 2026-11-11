package tray

import (
	"errors"

	"github.com/openidx/openidx/agent/internal/desktoppam"
)

// refusalAction is what the tray offers after a refused connect.
type refusalAction int

const (
	// actionTell: show the server's reason; nothing to offer.
	actionTell refusalAction = iota
	// actionSignInFresh: the session's second factor is stale; offer a fresh
	// sign-in, after which the connection is one click away.
	actionSignInFresh
	// actionRequestAccess: the entry needs an approved access request; offer
	// to file one from here.
	actionRequestAccess
	// actionJustify: the entry asks why; collect a written reason
	// (openidx://justify) and file the request with it.
	actionJustify
)

// refusalActionFor maps a connect error to the flow the tray offers. Kept
// pure so the mapping is tested without a tray.
func refusalActionFor(err error) refusalAction {
	switch {
	case errors.Is(err, desktoppam.ErrStepUpRequired):
		return actionSignInFresh
	case errors.Is(err, desktoppam.ErrJustificationRequired):
		return actionJustify
	case errors.Is(err, desktoppam.ErrApprovalRequired):
		return actionRequestAccess
	}
	return actionTell
}
