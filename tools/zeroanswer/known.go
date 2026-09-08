package main

// knownZeroAnswers is the backlog: aggregate queries whose error is still
// discarded, each with the verdict from reading what the caller does with the
// zero it is left holding.
//
// Keys are the file plus a hash of the statement's normalized text and its
// destination, close to the scheme tools/sqlprepare uses. Moving a query down a
// file keeps its entry; EDITING the query does not, because an edited query has
// to be re-read -- which is the behaviour wanted from a list whose whole
// purpose is to stop being needed.
//
// THE REGISTER IS EMPTY, and that is the point. It opened at 83, after
// internal/audit had already gone from 73 to 0, and every entry left it by the
// query being fixed. What was on it:
//
//	attestation      a failed pending-count AUTO-COMPLETED a certification
//	                 campaign, stamped completed_at and published
//	                 review.completed. An access certification closed without
//	                 the access being certified, with an audit trail saying it
//	                 was. Its sibling counts drew the progress bar.
//	continuous_auth  velocity risk scored 0 when its query failed -- and the
//	                 comment above it already recorded that this factor scored
//	                 0 for its ENTIRE LIFE because it read a table that does
//	                 not exist. The query was fixed; the discarded error that
//	                 hid it was not.
//	governance       campaign_runs.reviewed_items and total_items are the
//	                 permanent record of how big a certification campaign was
//	                 and how much of it was reviewed. Failed counts were
//	                 written into both as zero. A third: a failed EXISTS added
//	                 a duplicate pending approval on every escalation.
//	health_checks    the Relations & Integrity Doctor reported "ok" for a check
//	                 it could not run, which is the one answer an integrity
//	                 check must never give from no evidence.
//	portal           the end user's own security page told somebody who has
//	                 enrolled MFA that they had none.
//	risk             four of five scored factors bias harsher when their query
//	                 fails; one biases quieter, so a failed count of recent
//	                 failed logins removed the brute-force signal from the
//	                 score entirely.
//	admin, identity  the analytics, capacity, entitlement and sign-in
//	                 dashboards, which rendered "0 failed logins, 0 high-risk
//	                 sign-ins, 0 open alerts" -- what a healthy install also
//	                 looks like -- on the surfaces where somebody decides
//	                 whether to look further.
//	the list totals  published apps, proxy routes, known devices: 0 served in
//	                 the same response that carried the rows.
//
// An empty map is not a disabled check. `zeroanswer -fail` fails on any new
// finding, so the next aggregate whose error is thrown away stops the build
// rather than joining a list.
var knownZeroAnswers = map[string]string{}
