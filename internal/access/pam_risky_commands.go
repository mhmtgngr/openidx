// Package access — warnings for risky commands in privileged SSH sessions
// (org_pam_policy.risky_command_patterns, migration 243).
//
// After a recorded SSH entry session ends, the lifecycle sweep reads its text
// transcript (guacd's typescript, pam_launch.go), strips the terminal's
// control sequences, and matches every line against the organization's
// patterns. A session with matches raises one pam.risky_command audit event
// (with the matching lines, which stay inside openidx) and one
// pam.session.risky_command webhook (patterns and line numbers only: the
// transcript's text does not leave the install through a webhook).
//
// It warns after the fact; it blocks nothing. What it reads is what the
// terminal showed, so it sees typed commands and their output alike (a line
// printed by `cat` can match too), and someone who wants to hide a command
// from it can (quoting, aliases, a script). Live blocking is issue #976.
//
// Each session is scanned once: commands_scanned_at is the claim, written
// before anything is announced, so two replicas cannot both warn.
package access

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/webhooks"
)

const (
	// maxRiskyCommandPatterns and maxRiskyCommandPatternLen bound the policy.
	maxRiskyCommandPatterns   = 50
	maxRiskyCommandPatternLen = 200
	// riskyScanMaxBytes bounds how much of one transcript a tick reads.
	riskyScanMaxBytes = 64 << 20
	// riskyScanMaxMatches bounds what one session's warning carries.
	riskyScanMaxMatches = 20
	// riskyLineMaxLen is how much of a matching line the audit event keeps.
	riskyLineMaxLen = 240
	// riskyScanSettle is how long after a session ends its transcript is left
	// for guacd to finish writing.
	riskyScanSettleMinutes = 2
)

// compileRiskyCommandPatterns validates and compiles an organization's list.
// RE2 runs in time linear in the input, so a pattern cannot stall the sweep.
func compileRiskyCommandPatterns(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) > maxRiskyCommandPatterns {
		return nil, fmt.Errorf("at most %d risky command patterns", maxRiskyCommandPatterns)
	}
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return nil, errors.New("a risky command pattern is empty")
		}
		if len(p) > maxRiskyCommandPatternLen {
			return nil, fmt.Errorf("a risky command pattern is longer than %d characters", maxRiskyCommandPatternLen)
		}
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("risky command pattern %q: %v", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// terminalLineText turns one line of a typescript into the text the terminal
// showed: escape sequences (CSI, OSC, two-byte) removed, backspaces applied,
// carriage returns and other control bytes dropped.
func terminalLineText(line []byte) string {
	out := make([]rune, 0, len(line))
	for i := 0; i < len(line); {
		b := line[i]
		switch {
		case b == 0x1b && i+1 < len(line) && line[i+1] == '[': // CSI
			i += 2
			for i < len(line) && (line[i] < 0x40 || line[i] > 0x7e) {
				i++
			}
			i++
		case b == 0x1b && i+1 < len(line) && line[i+1] == ']': // OSC, to BEL or ST
			i += 2
			for i < len(line) && line[i] != 0x07 && !(line[i] == 0x1b && i+1 < len(line) && line[i+1] == '\\') {
				i++
			}
			if i < len(line) && line[i] == 0x1b {
				i++
			}
			i++
		case b == 0x1b: // other escapes: intermediates (e.g. "(" of a charset) then one final byte
			i++
			for i < len(line) && line[i] >= 0x20 && line[i] <= 0x2f {
				i++
			}
			i++
		case b == 0x08: // backspace
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			i++
		case b < 0x20 || b == 0x7f:
			if b == '\t' {
				out = append(out, ' ')
			}
			i++
		default:
			r, n := utf8.DecodeRune(line[i:])
			out = append(out, r)
			i += n
		}
	}
	return string(out)
}

type riskyMatch struct {
	Line    int    `json:"line"`
	Pattern string `json:"pattern"`
	Text    string `json:"text"`
}

// scanTypescript matches every line of a transcript against patterns. It
// returns the first riskyScanMaxMatches matches, the total count, and whether
// the read stopped at riskyScanMaxBytes. The [BEGIN/END TYPESCRIPT] markers
// guacd writes are skipped.
func scanTypescript(r io.Reader, patterns []string, res []*regexp.Regexp) ([]riskyMatch, int, bool, error) {
	lr := &io.LimitedReader{R: r, N: riskyScanMaxBytes}
	br := bufio.NewReaderSize(lr, 64<<10)
	var matches []riskyMatch
	total, lineNo := 0, 0
	for {
		raw, err := br.ReadBytes('\n')
		if len(raw) > 0 {
			lineNo++
			text := strings.TrimSpace(terminalLineText(raw))
			if text != "" && text != "[BEGIN TYPESCRIPT]" && text != "[END TYPESCRIPT]" {
				for i, re := range res {
					if re.MatchString(text) {
						total++
						if len(matches) < riskyScanMaxMatches {
							if len(text) > riskyLineMaxLen {
								text = strings.ToValidUTF8(text[:riskyLineMaxLen], "") + "…"
							}
							matches = append(matches, riskyMatch{Line: lineNo, Pattern: patterns[i], Text: text})
						}
						break // one warning per line
					}
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return matches, total, lr.N <= 0, nil
			}
			return matches, total, false, err
		}
	}
}

// openTypescriptForScan opens a transcript, through the decryptor when the
// file is sealed. The answer is taken from the file, not from the row: the
// sealer encrypts before it stamps, so between the two a row says plaintext
// over ciphertext.
func (s *Service) openTypescriptForScan(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if s.guacRecordingRing != nil && s.guacRecordingRing.Enabled() {
		var probe [1]byte
		n, perr := newDecryptingReader(f, s.guacRecordingRing, guacRecordingSessionKey(path)).Read(probe[:])
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		if n > 0 && perr == nil {
			return struct {
				io.Reader
				io.Closer
			}{newDecryptingReader(f, s.guacRecordingRing, guacRecordingSessionKey(path)), f}, nil
		}
	}
	return f, nil
}

// claimRiskyCommandScan stamps a session scanned and is the claim: only the
// replica whose write lands announces the warning.
func (s *Service) claimRiskyCommandScan(ctx context.Context, sessionID, orgID string, count *int) (bool, error) {
	tag, err := s.db.Pool.Exec(ctx, `UPDATE pam_entry_sessions SET commands_scanned_at = NOW(), risky_command_count = $1
		WHERE id = $2 AND org_id = $3 AND commands_scanned_at IS NULL`, count, sessionID, orgID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// scanRiskyCommands scans the transcripts of recently ended, recorded SSH
// entry sessions in organizations that have patterns, and warns.
func (s *Service) scanRiskyCommands(ctx context.Context) {
	if s.config == nil || s.config.GuacamoleRecordingPath == "" || s.db == nil || s.db.Pool == nil {
		return
	}
	root := s.config.GuacamoleRecordingPath
	rows, err := s.db.Pool.Query(ctx,
		//orgscope:ignore install-wide lifecycle sweep; each session is claimed and announced under the org of its own row
		`SELECT s.id::text, s.org_id::text, COALESCE(s.user_id::text, ''), s.entry_id::text, e.name,
		        s.recording_path, p.risky_command_patterns
		   FROM pam_entry_sessions s
		   JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		   JOIN org_pam_policy p ON p.org_id = s.org_id
		  WHERE s.status <> 'active' AND s.protocol = 'ssh'
		    AND COALESCE(s.recording_path, '') <> ''
		    AND s.commands_scanned_at IS NULL AND s.recording_purged_at IS NULL
		    AND s.ended_at < NOW() - make_interval(mins => $1)
		    AND s.ended_at > NOW() - interval '7 days'
		    AND cardinality(p.risky_command_patterns) > 0
		  ORDER BY s.ended_at
		  LIMIT 50`, riskyScanSettleMinutes)
	if err != nil {
		s.logger.Warn("lifecycle sweep: listing sessions for the risky command scan failed", zap.Error(err))
		return
	}
	type job struct {
		id, orgID, userID, entryID, entryName, path string
		patterns                                    []string
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.orgID, &j.userID, &j.entryID, &j.entryName, &j.path, &j.patterns); err == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	for _, j := range jobs {
		res, err := compileRiskyCommandPatterns(j.patterns)
		if err != nil {
			// Validated on write; a row that fails now is skipped, not guessed at.
			s.logger.Warn("lifecycle sweep: an organization's risky command patterns do not compile",
				zap.String("org_id", j.orgID), zap.Error(err))
			continue
		}
		ts := pamTypescriptFiles(j.path)[0]
		var count *int
		var matches []riskyMatch
		var truncated bool
		if isUnderRoot(ts, root) {
			f, oerr := s.openTypescriptForScan(ts)
			switch {
			case oerr == nil:
				m, n, tr, serr := scanTypescript(f, j.patterns, res)
				f.Close()
				if serr != nil {
					s.logger.Warn("lifecycle sweep: reading a transcript for the risky command scan failed; retrying next tick",
						zap.String("session_id", j.id), zap.Error(serr))
					continue
				}
				matches, truncated, count = m, tr, &n
			case errors.Is(oerr, os.ErrNotExist):
				// No transcript (an RDP-less SSH launch from before step 4,
				// or one guacd never wrote): stamped, count left NULL.
			default:
				s.logger.Warn("lifecycle sweep: opening a transcript for the risky command scan failed; retrying next tick",
					zap.String("session_id", j.id), zap.Error(oerr))
				continue
			}
		}
		octx := orgctx.With(ctx, orgctx.Org{ID: j.orgID})
		claimed, err := s.claimRiskyCommandScan(octx, j.id, j.orgID, count)
		if err != nil || !claimed {
			if err != nil {
				s.logger.Warn("lifecycle sweep: stamping a risky command scan failed", zap.String("session_id", j.id), zap.Error(err))
			}
			continue
		}
		if count == nil || *count == 0 {
			continue
		}
		s.logger.Info("lifecycle sweep: risky commands in a privileged session",
			zap.String("session_id", j.id), zap.Int("matches", *count))
		if s.auditService != nil {
			if err := s.auditService.RecordEvent(octx, "openidx", "pam.risky_command", "", j.userID, "",
				map[string]interface{}{"session_id": j.id, "entry_id": j.entryID, "entry_name": j.entryName,
					"match_count": *count, "matches": matches, "truncated": truncated}); err != nil {
				s.logger.Warn("lifecycle sweep: could not audit a risky command warning", zap.Error(err))
			}
		}
		lines := make([]map[string]interface{}, 0, len(matches))
		for _, m := range matches {
			lines = append(lines, map[string]interface{}{"line": m.Line, "pattern": m.Pattern})
		}
		s.publishPamEvent(j.orgID, webhooks.EventPamRiskyCommand, map[string]interface{}{
			"session_id": j.id, "entry_id": j.entryID, "entry_name": j.entryName, "user_id": j.userID,
			"match_count": *count, "matches": lines, "truncated": truncated,
		})
	}
}
