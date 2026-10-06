# `openidx://` deep-link registration

The Add-a-device wizard shows a QR / link of the form:

```
openidx://enroll?code=<enrollment-code>&server=<https://server>
```

When the OS opens it, the agent is invoked as `openidx-agent "openidx://enroll?..."`.
`main.go` detects the `openidx://` argument and rewrites it into
`enroll --code <code> --server <server>`. Each platform must register the agent
as the handler for the `openidx` URL scheme:

## Linux
Shipped automatically by the `.deb`/`.rpm` (see `nfpm.yaml`): the package installs
`openidx.desktop` (with `MimeType=x-scheme-handler/openidx;`) and its
`postinstall.sh` runs `xdg-mime default` + `update-desktop-database`.

## Windows (MSI / WiX)
The MSI registers the scheme (component `UrlSchemeOpenidx` in
`packaging/wix/OpenIDX.wxs`): `HKCR\openidx` with `URL Protocol`, and
`shell\open\command` = `"<install dir>\openidx-agent.exe" "%1"`.

The browser opens the link in the signed-in user's own process. Enrolment
writes `%ProgramData%\OpenIDX\agent\agent.json`, which only SYSTEM and
administrators may write, so the agent re-launches itself elevated (one UAC
prompt), enrols, starts the `OpenIDXAgent` service if it is installed and
stopped, and shows the outcome in a message box. The tray may already be
running unenrolled; it picks the server up from `agent.json` within its next
status tick, and the service, which waits for an enrolment rather than
stopping, starts the posture loop within half a minute on its own.

## macOS (.pkg app bundle)
Add to the app bundle's `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLName</key><string>org.openidx.agent</string>
    <key>CFBundleURLSchemes</key><array><string>openidx</string></array>
  </dict>
</array>
```
(Built in CI on the macOS runner with `pkgbuild`.)

## Manual fallback
Every platform keeps a manual path: `openidx-agent enroll --code <code> --server <url>`,
and the wizard shows a **Copy code** button. Deep-link registration is a
convenience, never a requirement.
