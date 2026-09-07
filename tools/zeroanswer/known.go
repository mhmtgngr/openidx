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
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so the
// only way an entry leaves is the query being fixed.
//
// It opened at 83, after internal/audit went from 73 to 0. Twenty-eight have
// left it since. Four went in the commit that seeded it -- the four where the
// zero was not a wrong number on a screen:
//
//	attestation.go   a failed pending-count AUTO-COMPLETED the certification
//	                 campaign, stamped completed_at and published
//	                 review.completed. An access certification closed without
//	                 the access being certified, with an audit trail saying it
//	                 was.
//	continuous_auth  velocity risk scored 0 when its query failed -- and the
//	                 comment above it already recorded that this factor scored
//	                 0 for its ENTIRE LIFE because it read a table that does
//	                 not exist. The query was fixed; the discarded error that
//	                 hid it was not.
//	                 The known-device check is fail-closed and now says so.
//	governance       campaign_runs.reviewed_items is the permanent record of
//	                 how much of a campaign was reviewed, and a failed count
//	                 was written into it as zero.
//
// Twenty-four more went in the commit after it: the pagination totals that read
// 0 beside the rows they count, the Relations & Integrity Doctor that reported
// 'ok' for a check it could not run, the end-user security page that told
// somebody with MFA enrolled that they had none, and the whole risk engine --
// where one factor biases the score DOWN when its query fails, so a failed
// count of recent failed logins removed the brute-force signal entirely.
//
// What is left is the analytics and reporting surfaces of internal/admin and
// internal/identity, plus three EXISTS gates. A compliance report is where this
// defect is worst, because the zero is printed as evidence and read as one; a
// dashboard is where it is most common.
//
// Some entries are fail-closed and say so: an unreadable known-device or
// known-IP check makes a login look LESS familiar, which is the safe direction.
// They are still on the list, because a control that silently degrades is a
// control nobody knows has degraded.
var knownZeroAnswers = map[string]string{
	// internal/access/quick_links.go
	"internal/access/quick_links.go#cd14fc8d0c70": "validateQuickLink &exists -- fail-closed: a failed EXISTS rejects the quick link rather than publishing one",

	// internal/admin/ai_agents.go
	"internal/admin/ai_agents.go#358a405453cf": "handleAIAgentAnalytics &active -- the AI-agent analytics tiles read 0",
	"internal/admin/ai_agents.go#30278aea0805": "handleAIAgentAnalytics &expiringCreds -- the AI-agent analytics tiles read 0",
	"internal/admin/ai_agents.go#697a58a2c262": "handleAIAgentAnalytics &recentFailures -- the AI-agent analytics tiles read 0",
	"internal/admin/ai_agents.go#beb6f8f7b85f": "handleAIAgentAnalytics &suspended -- the AI-agent analytics tiles read 0",
	"internal/admin/ai_agents.go#c322738c2277": "handleAIAgentAnalytics &total -- the AI-agent analytics tiles read 0",

	// internal/admin/ai_intelligence.go
	"internal/admin/ai_intelligence.go#795218689a13": "computeOrgIntelligence &logins24h -- the org intelligence summary reads 0 logins in 24 hours",

	// internal/admin/ai_recommendations.go
	"internal/admin/ai_recommendations.go#db110ff3bb8f": "handleRecommendationStats &accepted -- the recommendation acceptance rate is computed from a zero it did not measure",
	"internal/admin/ai_recommendations.go#3ab37d49e756": "handleRecommendationStats &totalResolved -- the recommendation acceptance rate is computed from a zero it did not measure",

	// internal/admin/analytics_enhanced.go
	"internal/admin/analytics_enhanced.go#a680f8b4f593": "handleAuthAnalyticsDashboard &failedLogins -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#3ea43752459f": "handleAuthAnalyticsDashboard &mfaLogins -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#1506f6894953": "handleAuthAnalyticsDashboard &successLogins -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#9e0cf559337a": "handleAuthAnalyticsDashboard &totalLogins -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#3312acedb4c1": "handleFeatureAdoption &totalUsers -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#30158585377c": "handleUsageAnalytics &activeSessions -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#93dd4ab03336": "handleUsageAnalytics &dau -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#b67ebddecf8d": "handleUsageAnalytics &mau -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#0022fd373e7e": "handleUsageAnalytics &newUsersToday -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#9a4ce120deca": "handleUsageAnalytics &totalApplications -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#93cd779bd070": "handleUsageAnalytics &totalGroups -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#93849baa61d5": "handleUsageAnalytics &totalUsers -- the analytics dashboard renders the zero as a measurement",
	"internal/admin/analytics_enhanced.go#bbe2acd97687": "handleUsageAnalytics &wau -- the analytics dashboard renders the zero as a measurement",

	// internal/admin/attestation.go
	"internal/admin/attestation.go#73b48e9e4f01": "handleAttestationProgress &certified -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#196601f0cbf2": "handleAttestationProgress &delegated -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#57c9240eeae5": "handleAttestationProgress &pending -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#f2ed97c40b5f": "handleAttestationProgress &revoked -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#3ccd8de8bfbb": "handleAttestationProgress &total -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#112b7c2579fa": "handleGetAttestationCampaign &ac.CertifiedCount -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#a91d72950661": "handleGetAttestationCampaign &ac.PendingCount -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#0af9968c9ed6": "handleGetAttestationCampaign &ac.RevokedCount -- the certification campaign reports a count it did not take",
	"internal/admin/attestation.go#8e7b1dac84c1": "handleGetAttestationCampaign &ac.TotalItems -- the certification campaign reports a count it did not take",

	// internal/admin/predictive_analytics.go
	"internal/admin/predictive_analytics.go#640e3a56c62f": "handleCapacityForecast &activeSessions -- the capacity forecast is projected from a zero it did not measure",
	"internal/admin/predictive_analytics.go#3312acedb4c1": "handleCapacityForecast &totalUsers -- the capacity forecast is projected from a zero it did not measure",
	"internal/admin/predictive_analytics.go#fbee2c02880c": "handlePredictionsSummary &activeUsers -- the capacity forecast is projected from a zero it did not measure",
	"internal/admin/predictive_analytics.go#0a88e9393e4d": "handlePredictionsSummary &peakSessions -- the capacity forecast is projected from a zero it did not measure",
	"internal/admin/predictive_analytics.go#93849baa61d5": "handlePredictionsSummary &totalUsers -- the capacity forecast is projected from a zero it did not measure",

	// internal/admin/service.go
	"internal/admin/service.go#dbd9683c05fe": "GetEntitlementStats &appCount -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#ddb9fd0a0962": "GetEntitlementStats &groupCount -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#024ae7b74463": "GetEntitlementStats &roleCount -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#4a88a40131b8": "handleRiskAnalytics &activeAlerts -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#a0358bda7b7a": "handleRiskAnalytics &avgRiskScore -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#1e2eacb53271": "handleRiskAnalytics &highRiskLogins24h -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#a01a5f82e4af": "handleSyncDirectory &exists -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#01a1bc749577": "handleUserAnalytics &active -- the admin dashboard renders the zero as a measurement",
	"internal/admin/service.go#7781f6c0d908": "handleUserAnalytics &total -- the admin dashboard renders the zero as a measurement",

	// internal/governance/request.go
	"internal/governance/request.go#f486e318f358": "checkEscalations &exists -- a failed EXISTS inserts a duplicate pending approval on escalation",

	// internal/governance/service.go
	"internal/governance/service.go#7bbbaf4a9459": "RunCampaign &totalItems -- the campaign record keeps a count nobody measured",

	// internal/identity/device_trust_approval.go
	"internal/identity/device_trust_approval.go#867ffa905592": "isKnownIP &count -- fail-closed: an unreadable known-IP check makes the login look less familiar, not more",

	// internal/identity/handlers_analytics.go
	"internal/identity/handlers_analytics.go#828e5a0f0571": "getLoginSummary &summary.AverageRiskScore -- the login analytics dashboard renders the zero as a measurement",
	"internal/identity/handlers_analytics.go#01983c0e60dc": "getLoginSummary &summary.HighRiskLogins -- the login analytics dashboard renders the zero as a measurement",
	"internal/identity/handlers_analytics.go#7b6e595aaf16": "getLoginSummary &summary.MFAChallenges -- the login analytics dashboard renders the zero as a measurement",
	"internal/identity/handlers_analytics.go#6630f14ef176": "getLoginSummary &summary.NewDevices -- the login analytics dashboard renders the zero as a measurement",
	"internal/identity/handlers_analytics.go#4545a57e9e38": "getLoginSummary &summary.TotalLogins -- the login analytics dashboard renders the zero as a measurement",
	"internal/identity/handlers_analytics.go#479982d91ad4": "getLoginSummary &summary.UniqueUsers -- the login analytics dashboard renders the zero as a measurement",
	"internal/identity/handlers_analytics.go#ee198ac75337": "getRiskDistribution &count -- the login analytics dashboard renders the zero as a measurement",
}
