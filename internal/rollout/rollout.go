// Package rollout judges how an agent update is going and what the next step
// is. It is pure: the caller gathers the evidence, this decides.
//
// The rules decide and nothing else does: the verdict, the reasons and the
// proposed step come from here, never from a model. A model, where one is
// configured, may only put them into words.
package rollout

import (
	"strings"
	"time"
)

// Rings are the rollout steps an organization moves through, as a share of its
// fleet. 0 is "nobody"; a fleet is moved up one ring at a time.
var Rings = []int{5, 25, 50, 100}

// Thresholds. They are constants, not settings: a rollout that is judged by
// rules an operator cannot see changing is easier to trust than one that is not.
const (
	// SoakAfterChange is how long a ring is held after its last change before
	// the next one is proposed, so a slow failure has time to show.
	SoakAfterChange = time.Hour
	// FailureWindow is how long a failed update attempt counts.
	FailureWindow = 24 * time.Hour
	// ApplyingWindow is how long "applying" counts as in progress.
	ApplyingWindow = time.Hour
	// FailureShare is the share of attempts that may fail before the rollout
	// is called unhealthy, in percent.
	FailureShare = 20
	// SmallSample is the number of attempts at or below which a single failure
	// is enough: with five devices one failing is one in five.
	SmallSample = 5
	// ReadyShare is the share of live devices in the ring that must already be
	// on the target before the next ring is proposed, in percent.
	ReadyShare = 90
)

// Update states a device reports.
const (
	UpdateOK       = "ok"
	UpdateFailed   = "failed"
	UpdateApplying = "applying"
	UpdateHeld     = "held"
)

// Settings is the organization's update ring.
type Settings struct {
	Percent int
	Paused  bool
	// ChangedAt is when the ring last changed.
	ChangedAt time.Time
}

// Device is one active device.
type Device struct {
	ID      string
	Version string
	// Live is whether it reported recently.
	Live bool
	// InRing is whether the ring currently reaches it.
	InRing bool
	// Update is the outcome of its last update attempt; "" when none.
	Update   string
	UpdateAt time.Time
}

// Input is the evidence.
type Input struct {
	Now time.Time
	// Target is the version the fleet is being moved to: the pin, or the
	// channel's current release. "" when it cannot be told.
	Target   string
	Settings Settings
	Devices  []Device
}

// Status is the headline.
type Status string

const (
	StatusNoTarget  Status = "no_target"
	StatusPaused    Status = "paused"
	StatusUnhealthy Status = "unhealthy"
	StatusSoaking   Status = "soaking"
	StatusReady     Status = "ready"
	StatusComplete  Status = "complete"
)

// Reason codes. The console words each; a test checks that it does.
const (
	ReasonNoTarget   = "NO_TARGET"
	ReasonPaused     = "PAUSED"
	ReasonFailures   = "FAILURES"
	ReasonSoaking    = "SOAKING"
	ReasonApplying   = "APPLYING"
	ReasonWaiting    = "WAITING_ON_DEVICES"
	ReasonReady      = "READY"
	ReasonEmptyRing  = "EMPTY_RING"
	ReasonAllOnTgt   = "ALL_ON_TARGET"
	ReasonOfflineIgn = "OFFLINE_IGNORED"
)

// AllReasons lists every reason the engine can give.
var AllReasons = []string{ReasonNoTarget, ReasonPaused, ReasonFailures, ReasonSoaking, ReasonApplying,
	ReasonWaiting, ReasonReady, ReasonEmptyRing, ReasonAllOnTgt, ReasonOfflineIgn}

// Action is a step the engine proposes.
type Action string

const (
	// ActionPause holds the fleet on what it runs. Reversible and stops harm:
	// the one step that may be taken without a person.
	ActionPause Action = "pause"
	// ActionAdvance widens the ring. It changes what reaches more machines, so
	// a person always approves it.
	ActionAdvance Action = "advance"
)

// Proposal is the step the engine would take.
type Proposal struct {
	Action  Action `json:"action"`
	Percent int    `json:"percent,omitempty"`
}

// Counts is what the verdict rests on.
type Counts struct {
	Devices  int `json:"devices"`
	InRing   int `json:"in_ring"`
	OnTarget int `json:"on_target"`
	Behind   int `json:"behind"`
	Failed   int `json:"failed"`
	Applying int `json:"applying"`
	Offline  int `json:"offline"`
}

// Verdict is the judgement.
type Verdict struct {
	Status   Status    `json:"status"`
	Reasons  []string  `json:"reasons"`
	Counts   Counts    `json:"counts"`
	Proposal *Proposal `json:"proposal,omitempty"`
}

// SameVersion compares versions the way a device reports them: a leading "v"
// does not make a different release.
func SameVersion(a, b string) bool {
	return a != "" && strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// NextRing is the first ring above percent, or 0 when there is none.
func NextRing(percent int) int {
	for _, r := range Rings {
		if r > percent {
			return r
		}
	}
	return 0
}

// Evaluate judges the rollout.
func Evaluate(in Input) Verdict {
	v := Verdict{Reasons: []string{}}
	if in.Target == "" {
		v.Status = StatusNoTarget
		v.Reasons = append(v.Reasons, ReasonNoTarget)
		return v
	}
	c := &v.Counts
	for _, d := range in.Devices {
		c.Devices++
		if !d.InRing {
			continue
		}
		c.InRing++
		on := SameVersion(d.Version, in.Target)
		switch {
		case on:
			c.OnTarget++
		case !d.Live:
			c.Offline++
		default:
			c.Behind++
		}
		if !on && d.Update == UpdateFailed && in.Now.Sub(d.UpdateAt) <= FailureWindow {
			c.Failed++
		}
		if !on && d.Update == UpdateApplying && in.Now.Sub(d.UpdateAt) <= ApplyingWindow {
			c.Applying++
		}
	}
	if c.Offline > 0 {
		v.Reasons = append(v.Reasons, ReasonOfflineIgn)
	}

	// Attempts are what has been tried: on the target, failed, or in progress.
	attempts := c.OnTarget + c.Failed + c.Applying
	unhealthy := c.Failed > 0 && c.Failed*100 >= attempts*FailureShare && (c.Failed >= 2 || attempts <= SmallSample)
	if unhealthy {
		v.Reasons = append([]string{ReasonFailures}, v.Reasons...)
	}
	if in.Settings.Paused {
		v.Status = StatusPaused
		v.Reasons = append([]string{ReasonPaused}, v.Reasons...)
		return v
	}
	if unhealthy {
		v.Status = StatusUnhealthy
		v.Proposal = &Proposal{Action: ActionPause}
		return v
	}
	if in.Settings.Percent >= 100 && c.Behind == 0 && c.Applying == 0 {
		v.Status = StatusComplete
		v.Reasons = append(v.Reasons, ReasonAllOnTgt)
		return v
	}
	if in.Now.Sub(in.Settings.ChangedAt) < SoakAfterChange {
		v.Status = StatusSoaking
		v.Reasons = append(v.Reasons, ReasonSoaking)
		return v
	}
	if c.Applying > 0 {
		v.Status = StatusSoaking
		v.Reasons = append(v.Reasons, ReasonApplying)
		return v
	}
	if c.InRing > 0 && c.Behind > 0 && c.OnTarget*100 < (c.OnTarget+c.Behind)*ReadyShare {
		v.Status = StatusSoaking
		v.Reasons = append(v.Reasons, ReasonWaiting)
		return v
	}
	next := NextRing(in.Settings.Percent)
	if next == 0 {
		// The last ring is reached and everything live is on the target.
		v.Status = StatusComplete
		v.Reasons = append(v.Reasons, ReasonAllOnTgt)
		return v
	}
	v.Status = StatusReady
	if c.InRing == 0 {
		v.Reasons = append(v.Reasons, ReasonEmptyRing)
	} else {
		v.Reasons = append(v.Reasons, ReasonReady)
	}
	v.Proposal = &Proposal{Action: ActionAdvance, Percent: next}
	return v
}
