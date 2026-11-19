### Changed
- **The tray no longer treats "not signed in" as a fault.** The device's network
  works under the device's own identity whether or not a person is signed in;
  the sign-in only matters for My Connections (privileged sessions), claiming the
  device and a fresh second factor. The status line now leads with the device
  and says "not signed in (only My Connections needs it)" as information, in
  English and Turkish. When a session ends the tray no longer empties its menu or
  announces "Session expired": it keeps the connection names, and a click that
  needs a session signs in and then opens the connection by itself (one browser
  window at a time) instead of an English error box and a second click. "Open my
  apps" is always shown, since the browser signs the person in. About says whether
  a person is signed in.
- **The phone and desktop apps no longer show "Session expired" for an access
  token that a refresh token can renew.** The engine reported an hour-old access
  token as an ended session although it refreshes on demand.
