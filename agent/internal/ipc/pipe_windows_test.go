//go:build windows

package ipc

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileCreatePipeInstance is the named-pipe right that lets a caller add an
// instance to an existing pipe name. It shares its bit with FILE_APPEND_DATA.
const fileCreatePipeInstance = 0x0004

// TestThePipeDACLGrantsUsersNoInstanceCreationOrDACLWrite parses the SDDL the
// way the kernel will and reads the Authenticated Users ACE back as a mask.
func TestThePipeDACLGrantsUsersNoInstanceCreationOrDACLWrite(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(%q): %v", pipeSDDL, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("no DACL")
	}
	au, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		t.Fatalf("AU sid: %v", err)
	}
	found := false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(au) {
			continue
		}
		found = true
		mask := uint32(ace.Mask)
		for _, bad := range []struct {
			name string
			bit  uint32
		}{
			{"FILE_CREATE_PIPE_INSTANCE", fileCreatePipeInstance},
			{"WRITE_DAC", windows.WRITE_DAC},
			{"WRITE_OWNER", windows.WRITE_OWNER},
			{"GENERIC_WRITE", windows.GENERIC_WRITE},
			{"GENERIC_ALL", windows.GENERIC_ALL},
		} {
			if mask&bad.bit != 0 {
				t.Errorf("Authenticated Users ACE carries %s (mask 0x%x)", bad.name, mask)
			}
		}
		if mask&windows.GENERIC_READ == 0 && mask&windows.FILE_READ_DATA == 0 {
			t.Errorf("Authenticated Users ACE grants no read (mask 0x%x); the tray could not query", mask)
		}
	}
	if !found {
		t.Fatal("no ACE for Authenticated Users; the tray would be refused")
	}
}

// TestAReadOnlyClientStillReadsTheStatus is the positive half: with the
// tightened DACL and a GENERIC_READ-only dial, Query gets the service's answer.
func TestAReadOnlyClientStillReadsTheStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	want := Status{Enrolled: true, AgentID: "agent-1", ZitiEnrolled: true}
	errCh := make(chan error, 1)
	go func() { errCh <- Serve(ctx, func() Status { return want }) }()

	var got *Status
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err = Query()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got.AgentID != want.AgentID || !got.Enrolled || !got.ZitiEnrolled {
		t.Fatalf("Query = %+v, want %+v", *got, want)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
