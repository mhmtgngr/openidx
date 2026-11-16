### Added
- **"Why can't I connect?" in the Windows tray.** The item runs the same
  device-side check as `openidx-agent doctor` and shows what is wrong and what
  to do, in the tray's language.
- **Support code.** When the check finds a problem it prints a short code
  (`OX1-…`) that names the failed checks and nothing else: no host name,
  address or device identifier. A user whose device cannot reach the server
  can read it to IT.
- **Doctor on the client's control socket.** `GET /doctor` and
  `POST /doctor/repair` (`?lang=en|tr`) return the diagnosis already worded,
  for the desktop client to draw.
