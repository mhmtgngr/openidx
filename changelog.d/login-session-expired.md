### Fixed
- **An expired sign-in no longer survives a reload.** The login page kept the
  pending sign-in's id in the tab and resubmitted it on every reload, so once
  it had expired the page answered "invalid or expired login session" forever.
  `POST /oauth/login` now refuses it with `login_session_expired`, and the page
  drops the id: a console sign-in starts over by itself, and a sign-in that
  began in another app says to go back there and start again.
