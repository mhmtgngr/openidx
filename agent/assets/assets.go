// Package assets embeds the OpenIDX client's static branding assets (the app
// icon) so they ship inside the single agent binary — no external files to
// deploy. The icon is a multi-resolution Windows ICO (16–256 px) used for the
// system-tray icon and, at build time, the MSI/shortcut icon.
package assets

import _ "embed"

// OpenIDXICO is the OpenIDX shield/keyhole icon in Windows ICO format
// (multiple sizes). Pass it to systray.SetIcon on Windows.
//
//go:embed openidx.ico
var OpenIDXICO []byte
