// Package access — ending privileged sessions left idle (org_pam_policy
// idle_timeout_minutes).
//
// Guacamole reports no per-session activity, so the broker cannot be asked.
// The recording can: guacd writes the user's input into it (recording-include-
// keys is always set, buildPamGuacParams) as timestamped `key`, `mouse` and
// `touch` instructions, and it writes `sync` every frame, about once a second
// even on an idle SSH screen. Measured on guacd 1.6.0: an idle SSH session's
// recording keeps growing (syncs), an idle RDP one barely does, and in both a
// keystroke or a pointer move appears as an instruction carrying its own
// timestamp. So the idle time is the gap between the recording's latest sync
// (its own clock: guacd's timestamps are not wall time) and its latest input.
//
// Only a recorded session can be judged; an unrecorded one is left alone,
// and the console says idle timeouts apply to recorded sessions. External
// users' sessions are always recorded. The recording is read, never changed
// (an active session is never sealed), and only its tail.
package access

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// sessionEndIdle: no input reached the session for the policy's idle timeout.
const sessionEndIdle = "idle_timeout"

// pamIdleTailBytes is how much of a recording's end is read per tick. An idle
// SSH session writes ~25 bytes of sync per second, so 4 MiB holds well over a
// day of idleness; a tail that holds no input is judged only when it is the
// whole recording (idleFor).
const pamIdleTailBytes = 4 << 20

// recordingActivity is what a recording's tail says about when the session
// was last used, on the recording's own clock (milliseconds).
type recordingActivity struct {
	LastSync  int64 // the recording's "now"
	LastInput int64 // 0 when the tail holds no input
	FirstSync int64 // the earliest sync in the tail
}

// idleFor is how long the session has gone without input, as far as the tail
// can tell, and whether it can tell at all.
//
// With no input in the tail, the session has had none at least since the tail
// began, but a busy screen (RDP video, a scrolling log) can fill the tail in
// minutes, and its first sync would then make an active user look idle. So a
// tail without input is judged only when it is the whole recording, which then
// shows no input since the session started; otherwise the answer is "cannot
// tell" and the session is left alone. Wrongly ending a session is the worse
// mistake.
func (a recordingActivity) idleFor(whole bool) (time.Duration, bool) {
	since := a.LastInput
	if since == 0 {
		if !whole {
			return 0, false
		}
		since = a.FirstSync
	}
	if a.LastSync == 0 || since == 0 || a.LastSync < since {
		return 0, false
	}
	return time.Duration(a.LastSync-since) * time.Millisecond, true
}

// scanRecordingActivity parses Guacamole protocol instructions from the end
// of a recording. It skips to the first instruction boundary in the tail and
// tolerates a truncated last instruction (guacd may be mid-write).
func scanRecordingActivity(tail []byte, fromStart bool) recordingActivity {
	var a recordingActivity
	i := 0
	if !fromStart {
		// Resynchronise on an instruction boundary: a ';' followed by a
		// length digit.
		for i < len(tail)-1 && !(tail[i] == ';' && tail[i+1] >= '0' && tail[i+1] <= '9') {
			i++
		}
		i++
	}
	for i < len(tail) {
		var elems []string
		ok := true
		for {
			j := i
			for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
				j++
			}
			if j == i || j >= len(tail) || tail[j] != '.' {
				ok = false
				break
			}
			n, err := strconv.Atoi(string(tail[i:j]))
			if err != nil || j+1+n >= len(tail) {
				ok = false
				break
			}
			elems = append(elems, string(tail[j+1:j+1+n]))
			i = j + 1 + n
			if tail[i] == ';' {
				i++
				break
			}
			if tail[i] != ',' {
				ok = false
				break
			}
			i++
		}
		if !ok {
			break
		}
		switch elems[0] {
		case "sync":
			if len(elems) > 1 {
				if ts, err := strconv.ParseInt(elems[1], 10, 64); err == nil {
					if a.FirstSync == 0 {
						a.FirstSync = ts
					}
					a.LastSync = ts
				}
			}
		case "key", "mouse", "touch":
			// The timestamp is the instruction's last element.
			if ts, err := strconv.ParseInt(elems[len(elems)-1], 10, 64); err == nil {
				a.LastInput = ts
			}
		}
	}
	return a
}

// readRecordingTail returns the last pamIdleTailBytes of path and whether
// that is the whole file.
func readRecordingTail(path string) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	off := fi.Size() - pamIdleTailBytes
	whole := off <= 0
	if whole {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, false, err
	}
	b, err := io.ReadAll(io.LimitReader(f, pamIdleTailBytes))
	return b, whole, err
}

type pamIdleRow struct {
	id, orgID, userID, connID, guacUser, reach, path string
	limit                                            time.Duration
}

// endIdlePamEntrySessions ends active, recorded entry sessions whose
// recording shows no input for longer than their organization's idle
// timeout, through the broker-honest path the other ends use.
func (s *Service) endIdlePamEntrySessions(ctx context.Context) {
	root := s.config.GuacamoleRecordingPath
	if root == "" {
		return
	}
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide lifecycle reconcile sweep; each session is ended under the org of its own row
		`SELECT s.id::text, s.org_id::text, COALESCE(s.user_id::text, ''), COALESCE(s.guac_connection_id, ''),
		        COALESCE(s.guac_username, ''), COALESCE(e.reach_mode, ''), s.recording_path, p.idle_timeout_minutes
		   FROM pam_entry_sessions s
		   JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		   JOIN org_pam_policy p ON p.org_id = s.org_id
		  WHERE s.status = 'active' AND COALESCE(s.recording_path, '') <> ''
		    AND p.idle_timeout_minutes > 0
		    AND s.started_at < NOW() - make_interval(mins => p.idle_timeout_minutes)
		  ORDER BY s.started_at
		  LIMIT 200`)
	if err != nil {
		s.logger.Warn("lifecycle sweep: listing PAM sessions for the idle check failed", zap.Error(err))
		return
	}
	var cands []pamIdleRow
	for rows.Next() {
		var r pamIdleRow
		var mins int
		if err := rows.Scan(&r.id, &r.orgID, &r.userID, &r.connID, &r.guacUser, &r.reach, &r.path, &mins); err == nil {
			r.limit = time.Duration(mins) * time.Minute
			cands = append(cands, r)
		}
	}
	rows.Close()

	for _, r := range cands {
		if !isUnderRoot(r.path, root) {
			continue
		}
		tail, whole, err := readRecordingTail(r.path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				s.logger.Warn("lifecycle sweep: reading a recording for the idle check failed",
					zap.String("session_id", r.id), zap.Error(err))
			}
			continue // no recording yet: nothing to judge by
		}
		idle, known := scanRecordingActivity(tail, whole).idleFor(whole)
		if !known || idle <= r.limit {
			continue
		}
		octx := orgctx.With(ctx, orgctx.Org{ID: r.orgID})
		warn := func(step string, err error) {
			s.logger.Warn("lifecycle sweep: an idle PAM session was not ended (will retry next tick)",
				zap.String("step", step), zap.String("session_id", r.id), zap.Error(err))
		}
		for _, id := range s.endPamEntrySessionRows(octx, r.orgID,
			[]pamSessionRow{{rowID: r.id, connID: r.connID, guacUser: r.guacUser, reach: r.reach}}, warn) {
			s.logger.Info("lifecycle sweep: ended an idle PAM session",
				zap.String("session_id", id), zap.Duration("idle", idle))
			s.pamSessionEnded(r.orgID, id, sessionEndIdle, "")
			if s.auditService != nil {
				if err := s.auditService.RecordEvent(octx, "openidx", "pam.session_ended", "", r.userID, "",
					map[string]interface{}{"session_id": id, "reason": sessionEndIdle,
						"idle_minutes": int(idle.Minutes()), "limit_minutes": int(r.limit.Minutes())}); err != nil {
					s.logger.Warn("lifecycle sweep: could not audit an idle PAM session", zap.Error(err))
				}
			}
		}
	}
}
