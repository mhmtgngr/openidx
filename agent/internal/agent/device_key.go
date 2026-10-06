package agent

import (
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/devicekey"
	"github.com/openidx/openidx/agent/internal/transport"
)

// deviceKeyRetry is how often a device whose key the server does not hold
// yet offers it again (an older server, or one that was unreachable).
const deviceKeyRetry = 6 * time.Hour

// openDeviceKey finds or makes the device key. A variable so tests choose
// where keys come from; on Windows the real one creates a machine key.
var openDeviceKey = devicekey.OpenOrCreate

// bindDeviceKey loads the device key once, signs posture reports with it from
// then on, and, until the server holds it, offers it to the server.
//
// Best-effort throughout: a device that cannot make a key (no TPM and no
// usable software store, or a process without the rights to make a machine
// key) reports as it did before, and the server, holding no key for it,
// accepts that. The tray's loop never calls this: it reports nothing, and a
// machine key is the service's.
func (a *Agent) bindDeviceKey() {
	if a.RemoteSupportOnly {
		return
	}
	if a.deviceKey == nil {
		if a.deviceKeyFailed {
			return
		}
		k, err := openDeviceKey(a.configDir)
		if err != nil {
			a.deviceKeyFailed = true
			a.logger.Warn("no device key: posture reports are not signed, and the server cannot "+
				"tell this device's reports from a copy of its token", zap.Error(err))
			return
		}
		a.deviceKey = k
		transport.SetSigner(a.client, devicekey.Signer{Key: k, AgentID: a.config.AgentID})
		a.logger.Info("device key loaded; posture reports are signed", zap.String("kind", k.Kind()))
	}
	if a.config.DeviceKeyBound || time.Since(a.lastKeyOffer) < deviceKeyRetry {
		return
	}
	a.lastKeyOffer = time.Now()
	pub, err := devicekey.PublicKeyBase64(a.deviceKey)
	if err != nil {
		a.logger.Warn("could not encode the device key", zap.Error(err))
		return
	}
	signer := devicekey.Signer{Key: a.deviceKey, AgentID: a.config.AgentID}
	err = transport.NewClient(a.config.ServerURL, a.config.AuthToken, a.config.AgentID).
		RegisterDeviceKey(pub, a.deviceKey.Kind(), signer)
	switch {
	case err == nil:
		a.config.DeviceKeyBound = true
		if serr := a.config.Save(a.configDir); serr != nil {
			a.logger.Warn("the server holds the device key, but agent.json could not record it",
				zap.Error(serr))
		}
		a.logger.Info("the server now holds this device's key", zap.String("kind", a.deviceKey.Kind()))
	case errors.Is(err, transport.ErrDeviceKeyUnsupported):
		a.logger.Debug("the server does not take device keys yet; will offer it again later")
	case errors.Is(err, transport.ErrDeviceKeyConflict):
		a.logger.Error("the server holds a different key for this device, so its reports will be "+
			"refused until it is enrolled again", zap.Error(err))
	default:
		a.logger.Warn("offering the device key failed; will try again later", zap.Error(err))
	}
}
