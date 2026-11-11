package winservice

// startupSequence is the order Execute follows when the SCM starts the
// service: tell the SCM the service is Running FIRST, and only then begin the
// work that may be slow (reading and unsealing agent.json, the sealed
// enrol-token retry, the tray and IPC loops, a file another process still
// holds open during an MSI upgrade). The SCM gives a starting service a fixed
// window to connect and report Running; anything ahead of that report is a
// chance to miss it, and on upgrade that turns into MSI error 1920.
//
// It is a separate, platform-neutral function so the ordering is unit-tested
// on every OS rather than only by the Windows install smoke.
func startupSequence(reportRunning func(), slowWork ...func()) {
	reportRunning()
	for _, w := range slowWork {
		go w()
	}
}
