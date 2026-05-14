//go:build unix

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package provider

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	captureConstants "github.com/microsoft/retina/pkg/capture/constants"
	"github.com/microsoft/retina/pkg/capture/file"
	"github.com/microsoft/retina/pkg/log"
)

const (
	testCaptureFilePath = "/tmp/test.pcap"
	interfaceEth0       = "eth0"
	interfaceEth1       = "eth1"
	interfaceAny        = "any"
)

func TestSetupAndCleanup(t *testing.T) {
	captureName := "capture-test"
	nodeHostName := "node1"
	timestamp := file.Now()
	_, _ = log.SetupZapLogger(log.GetDefaultLogOpts())
	networkCaptureprovider := NewNetworkCaptureProvider(log.Logger().Named("test"))
	tmpFilename := file.CaptureFilename{CaptureName: captureName, NodeHostname: nodeHostName, StartTimestamp: timestamp}
	tmpCaptureLocation, err := networkCaptureprovider.Setup(tmpFilename)

	// remove temporary capture dir anyway in case Cleanup() fails.
	defer os.RemoveAll(tmpCaptureLocation)

	if err != nil {
		t.Errorf("Setup should have not fail with error %s", err)
	}
	if !strings.Contains(tmpCaptureLocation, captureName) {
		t.Errorf("Temporary capture dir name %s should contains capture name  %s", tmpCaptureLocation, captureName)
	}
	if !strings.Contains(tmpCaptureLocation, nodeHostName) {
		t.Errorf("Temporary capture dir name %s should contains node host name  %s", tmpCaptureLocation, nodeHostName)
	}
	if !strings.Contains(tmpCaptureLocation, file.TimeToString(timestamp)) {
		t.Errorf("Temporary capture dir name %s should contain timestamp  %s", tmpCaptureLocation, timestamp)
	}

	if _, statErr := os.Stat(tmpCaptureLocation); os.IsNotExist(statErr) {
		t.Errorf("Temporary capture dir %s should be created", tmpCaptureLocation)
	}

	err = networkCaptureprovider.Cleanup()
	if err != nil {
		t.Errorf("Cleanup should have not fail with error %s", err)
	}

	if _, err := os.Stat(tmpCaptureLocation); !os.IsNotExist(err) {
		t.Errorf("Temporary capture dir %s should be deleted", tmpCaptureLocation)
	}
}

// Helper function to check if command args contain specific interface
func hasInterface(cmd *exec.Cmd, expectedInterface string) bool {
	for i, arg := range cmd.Args {
		if arg == "-i" && i+1 < len(cmd.Args) && cmd.Args[i+1] == expectedInterface {
			return true
		}
	}
	return false
}

// Helper function to reset environment variables
func resetEnvVars() {
	os.Unsetenv(captureConstants.TcpdumpRawFilterEnvKey)
	os.Unsetenv(captureConstants.PacketSizeEnvKey)
	os.Unsetenv(captureConstants.CaptureInterfacesEnvKey)
}

// TestTcpdumpEmptyFilter verifies that empty filter falls back to default interface
// and that no unexpected or malicious arguments are injected.
func TestTcpdumpEmptyFilter(t *testing.T) {
	resetEnvVars()
	cmd := constructTcpdumpCommand(testCaptureFilePath, "")

	// Should fall back to "-i any"
	if !hasInterface(cmd, interfaceAny) {
		t.Errorf("Expected fallback to '-i any' with empty filter, but got args: %v", cmd.Args)
	}

	// Verify only expected args are present and no malicious content
	for _, arg := range cmd.Args {
		if arg != "tcpdump" && arg != "-w" && arg != testCaptureFilePath &&
			arg != "--relinquish-privileges=root" && arg != "-i" && arg != interfaceAny {
			t.Errorf("Unexpected argument '%s' found in empty filter command: %v", arg, cmd.Args)
		}
		// Check for malicious content
		if strings.Contains(arg, "/etc/passwd") || strings.Contains(arg, "evil") ||
			strings.Contains(arg, "rm -rf") || strings.HasPrefix(arg, "-z") {
			t.Errorf("Malicious content should not be present in command args: %v", cmd.Args)
		}
	}
}

func TestTcpdumpWithBPFFilter(t *testing.T) {
	resetEnvVars()
	// Test that a valid BPF filter is properly added to the tcpdump command
	// Note: Filter validation (e.g., rejecting '-' prefix) happens in CaptureNetworkPacket

	bpfFilter := "tcp port 80"

	cmd := constructTcpdumpCommand(testCaptureFilePath, bpfFilter)

	// Should have the BPF filter as an argument
	found := slices.Contains(cmd.Args, bpfFilter)
	if !found {
		t.Errorf("Expected BPF filter '%s' in args, but got: %v", bpfFilter, cmd.Args)
	}
}

func TestTcpdumpSpecificInterfaces(t *testing.T) {
	resetEnvVars()
	os.Setenv(captureConstants.CaptureInterfacesEnvKey, interfaceEth0+","+interfaceEth1)
	defer os.Unsetenv(captureConstants.CaptureInterfacesEnvKey)

	cmd := constructTcpdumpCommand(testCaptureFilePath, "")

	if !hasInterface(cmd, interfaceEth0) {
		t.Errorf("Expected tcpdump command to include '-i %s', but got args: %v", interfaceEth0, cmd.Args)
	}
	if !hasInterface(cmd, interfaceEth1) {
		t.Errorf("Expected tcpdump command to include '-i %s', but got args: %v", interfaceEth1, cmd.Args)
	}
	if hasInterface(cmd, interfaceAny) {
		t.Errorf("Expected tcpdump command not to include '-i any' when specific interfaces are set, but got args: %v", cmd.Args)
	}
}

func TestTcpdumpBPFFilterWithSpecificInterfaces(t *testing.T) {
	resetEnvVars()
	// Verify that BPF filter and specific interface selection work together
	// Both should be present in the command (they are independent features)
	bpfFilter := "tcp port 443"
	os.Setenv(captureConstants.CaptureInterfacesEnvKey, interfaceEth0+","+interfaceEth1)
	defer os.Unsetenv(captureConstants.CaptureInterfacesEnvKey)

	cmd := constructTcpdumpCommand(testCaptureFilePath, bpfFilter)

	// The BPF filter should be present
	found := slices.Contains(cmd.Args, bpfFilter)
	if !found {
		t.Errorf("Expected BPF filter '%s' in command, but got args: %v", bpfFilter, cmd.Args)
	}

	// Interfaces should still be present (BPF filter doesn't override interface selection)
	if !hasInterface(cmd, interfaceEth0) || !hasInterface(cmd, interfaceEth1) {
		t.Errorf("Expected both interfaces to be present with BPF filter, but got args: %v", cmd.Args)
	}
}

func TestTcpdumpCommandConstruction(t *testing.T) {
	// Default behavior tests
	t.Run("EmptyFilter", TestTcpdumpEmptyFilter)

	// Interface selection tests
	t.Run("SpecificInterfaceSelection", TestTcpdumpSpecificInterfaces)
	t.Run("InterfaceListWithEmptyEntries", TestTcpdumpInterfaceListWithEmptyEntries)

	// BPF filter tests
	t.Run("WithBPFFilter", TestTcpdumpWithBPFFilter)
	t.Run("BPFFilterWithSpecificInterfaces", TestTcpdumpBPFFilterWithSpecificInterfaces)
	t.Run("BPFFilterWithComplexExpression", TestTcpdumpBPFFilterComplexExpression)
	t.Run("BPFFilterWithTcpFlags", TestTcpdumpBPFFilterWithTcpFlags)

	// Option tests
	t.Run("PacketSizeOption", TestTcpdumpPacketSizeOption)
}

// TestTcpdumpBPFFilterComplexExpression validates that complex BPF filter expressions
// with multiple keywords and operators are passed as a single argument, not split on spaces.
// This is critical for security - splitting would allow flag injection attacks.
func TestTcpdumpBPFFilterComplexExpression(t *testing.T) {
	resetEnvVars()
	// Test a complex BPF filter that should remain as one argument
	bpfFilter := "tcp and (port 80 or port 443) and host 10.0.0.1"

	cmd := constructTcpdumpCommand(testCaptureFilePath, bpfFilter)

	// The entire filter must appear as a single argument
	found := slices.Contains(cmd.Args, bpfFilter)
	if !found {
		t.Errorf("Expected entire BPF filter '%s' as single argument, but got args: %v", bpfFilter, cmd.Args)
	}

	// Verify individual keywords are NOT separate arguments (which would indicate splitting)
	splitIndicators := []string{"tcp", "and", "port", "80", "or", "443", "host", "10.0.0.1"}
	for _, indicator := range splitIndicators {
		for _, arg := range cmd.Args {
			if arg == indicator {
				t.Errorf("BPF filter was incorrectly split: found '%s' as separate arg in: %v", indicator, cmd.Args)
			}
		}
	}
}

// TestTcpdumpBPFFilterWithTcpFlags verifies that BPF filters using TCP flag syntax
// with special characters like brackets, pipes, and ampersands are passed correctly.
// Example: tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn
func TestTcpdumpBPFFilterWithTcpFlags(t *testing.T) {
	resetEnvVars()
	// Test a BPF filter with TCP flags syntax and special characters
	bpfFilter := "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"

	cmd := constructTcpdumpCommand(testCaptureFilePath, bpfFilter)

	// Positive check: The entire filter must appear as a single argument
	found := slices.Contains(cmd.Args, bpfFilter)
	if !found {
		t.Errorf("Expected entire BPF filter '%s' as single argument, but got args: %v", bpfFilter, cmd.Args)
	}

	// Negative check: Verify the filter is not split on spaces (which would indicate incorrect handling)
	// These are the pieces that would appear if the filter were split on spaces
	splitIndicators := []string{"tcp[tcpflags]", "&", "(tcp-syn|tcp-ack)", "==", "tcp-syn"}
	for _, indicator := range splitIndicators {
		for _, arg := range cmd.Args {
			if arg == indicator {
				t.Errorf("BPF filter was incorrectly split: found '%s' as separate arg in: %v", indicator, cmd.Args)
			}
		}
	}
}

// TestTcpdumpInterfaceListWithEmptyEntries verifies handling of interface lists with empty values
func TestTcpdumpInterfaceListWithEmptyEntries(t *testing.T) {
	resetEnvVars()
	// Interface list with empty entries and extra spaces
	os.Setenv(captureConstants.CaptureInterfacesEnvKey, "eth0, ,eth1,,eth2, ")
	defer os.Unsetenv(captureConstants.CaptureInterfacesEnvKey)

	cmd := constructTcpdumpCommand(testCaptureFilePath, "")

	// Should only include non-empty interfaces
	if !hasInterface(cmd, interfaceEth0) {
		t.Errorf("Expected '-i eth0', but got args: %v", cmd.Args)
	}
	if !hasInterface(cmd, interfaceEth1) {
		t.Errorf("Expected '-i eth1', but got args: %v", cmd.Args)
	}
	// eth2 should be present
	if !hasInterface(cmd, "eth2") {
		t.Errorf("Expected '-i eth2', but got args: %v", cmd.Args)
	}
}

// TestTcpdumpPacketSizeOption verifies that packet size option is correctly added
func TestTcpdumpPacketSizeOption(t *testing.T) {
	resetEnvVars()
	os.Setenv(captureConstants.PacketSizeEnvKey, "1500")
	defer os.Unsetenv(captureConstants.PacketSizeEnvKey)

	cmd := constructTcpdumpCommand(testCaptureFilePath, "")

	// Should include -s 1500
	foundS := false
	foundSize := false
	for i, arg := range cmd.Args {
		if arg == "-s" {
			foundS = true
			if i+1 < len(cmd.Args) && cmd.Args[i+1] == "1500" {
				foundSize = true
			}
		}
	}
	if !foundS || !foundSize {
		t.Errorf("Expected '-s 1500' in tcpdump args, but got: %v", cmd.Args)
	}
}
