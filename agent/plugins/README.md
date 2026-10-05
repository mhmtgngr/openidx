# Agent plugins

A plugin adds posture checks to the agent. It is a folder under the
directory `plugin_dir` names in `agent.json`:

```
<plugin_dir>/
  hello/
    manifest.json   name, version, platforms, check_types, timeout_seconds
    hello           the executable (hello.exe, .bat or .cmd on Windows; hello or hello.sh elsewhere)
    plugin.sig      the publisher's signature
```

The agent runs the executable with its own privileges, which means SYSTEM
under the Windows service, on every check interval. It sends a JSON request
on stdin and reads a JSON result from stdout. `plugin-hello/` is a minimal
example. It is unsigned, so it loads only under `allow_unsigned_plugins`.

## What the agent checks before loading a plugin

- **Permissions.** The plugin directory, the plugin's folder, `manifest.json`
  and the executable must not be writable by an untrusted account. On Unix
  that means not writable by the group or by others. On Windows only SYSTEM,
  Administrators, TrustedInstaller and the agent's own account may own them
  or hold a right to change them.
- **Signature.** `plugin.sig` must verify against the publisher the agent
  trusts for updates. By default that is the pinned OpenIDX release key. If
  `update_trusted_cert` is set in `agent.json`, it is that certificate
  instead. The certificate's validity window is enforced.
- **Check names.** A plugin may not declare a check type the agent provides
  itself, such as `disk_encryption` or `os_version`, whether or not it is
  signed. Give your checks their own names.
- **The executable has not changed.** The executable's SHA-256 is recorded
  when the plugin is loaded and checked again before every run. If the file
  has changed, the check reports an error and the file is not run. Restart
  the agent to load a new version.

A plugin that fails any of these is skipped, and the agent logs the reason.

The signature covers `manifest.json` and the executable. Any other file in
the folder, such as a DLL or a script the executable loads, is protected
only by the folder's permissions. A plugin should therefore be a single
self-contained executable.

## Signing a plugin

The signature is RSA PKCS#1 v1.5 over SHA-256, base64-encoded, made with the
key of the trusted publisher. It is computed over these exact bytes:

```
openidx-agent-plugin/v1
name=<manifest name>
version=<manifest version>
manifest_sha256=<lowercase hex SHA-256 of manifest.json>
executable=<executable file name>
executable_sha256=<lowercase hex SHA-256 of the executable>
```

Each line ends with `\n`, the last one included. The agent prints these bytes
for you. It never handles a private key, so you sign the bytes with your own
tooling:

```sh
openidx-agent plugin digest --dir ./hello > input.txt
openssl dgst -sha256 -sign key.pem input.txt | base64 -w0 > ./hello/plugin.sig
```

Run `plugin digest` on the platform the plugin is for, because the
executable's file name is part of what is signed. Redirect its output with a
shell that writes bytes unchanged, such as bash or cmd.exe. PowerShell's `>`
can re-encode the text or change its line endings (Windows PowerShell writes
UTF-16), and a signature over that file will not verify. Sign again whenever
the manifest or the executable changes.

To sign your own plugins, set `update_trusted_cert` to your publisher's
certificate. That setting also replaces the pinned publisher for agent
updates, so the same key must then sign your update manifests too.

## `allow_unsigned_plugins`

`"allow_unsigned_plugins": true` in `agent.json` loads plugins without
checking their signature. It is meant for a lab where plugins are being
written. It does not belong on a managed fleet. It turns off only the
signature check: the permission checks, the reserved check names and the
check before every run still apply. Like `plugin_dir`, it is obeyed only from
an `agent.json` that only the service and administrators can write.
