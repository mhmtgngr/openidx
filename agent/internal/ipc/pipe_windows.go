//go:build windows

package ipc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Serve listens on the named pipe and returns the current status (from
// provider) as JSON to each client, until ctx is cancelled. Best-effort:
// individual connection errors are ignored.
func Serve(ctx context.Context, provider func() Status) error {
	cfg := &winio.PipeConfig{SecurityDescriptor: pipeSDDL}
	ln, err := winio.ListenPipe(PipeName, cfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go func() {
			defer conn.Close()
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = json.NewEncoder(conn).Encode(provider())
		}()
	}
}

// Query dials the service pipe and reads the current status. Returns an error
// if the service isn't running / the pipe isn't available.
//
// The pipe is opened for GENERIC_READ only. The default DialPipe asks for
// read and write, which the pipe's DACL no longer grants to a plain user (see
// pipeSDDL); the tray never writes to the service anyway.
func Query() (*Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := winio.DialPipeAccess(ctx, PipeName, windows.GENERIC_READ)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var s Status
	if err := json.NewDecoder(conn).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}
