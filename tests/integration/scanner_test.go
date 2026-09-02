package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"
)

func TestScannerEndToEnd(t *testing.T) {
	// 1. Setup Integration Environment
	fmt.Println("Starting integration environment...")
	// Start only MQTT first to get its IP
	exec.Command("docker-compose", "-f", "docker-compose.test.yml", "up", "-d", "test-mqtt").Run()

	// Get MQTT container IP
	ipCmd := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "integration-test-mqtt-1")
	mqttIPOut, err := ipCmd.Output()
	mqttIP := strings.TrimSpace(string(mqttIPOut))
	if err != nil || mqttIP == "" {
		// Fallback for different compose project names
		ipCmd = exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "integration_test-mqtt_1")
		mqttIPOut, _ = ipCmd.Output()
		mqttIP = strings.TrimSpace(string(mqttIPOut))
	}
	mqttIP = fmt.Sprintf("%s/32", mqttIP)
	fmt.Printf("DEBUG: Targeted MQTT container at %s\n", mqttIP)

	// Now start the scanner with the specific target via ENV
	os.Setenv("SCAN_RANGE", mqttIP)
	cmd := exec.Command("docker-compose", "-f", "docker-compose.test.yml", "up", "-d", "--build", "test-scanner")
	// Note: We need to override the command to use the detected IP.
	// Since docker-compose 'up' doesn't easily override 'command' via CLI for existing services,
	// we'll rely on the scanner's auto-detection if we don't pass -range,
	// OR we can just use the detected IP in the environment.
	// For this test, let's use a simpler approach: update the compose file to NOT have a range,
	// and let the scanner's new auto-detection find the network.

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to start docker-compose: %v\nOutput: %s", err, string(out))
	}
	defer func() {
		fmt.Println("Tearing down integration environment...")
		exec.Command("docker-compose", "-f", "docker-compose.test.yml", "down", "-v").Run()
	}()

	// 2. Connect to Test MQTT
	opts := mqtt.NewClientOptions().AddBroker("tcp://localhost:1883").SetClientID("test-verifier")
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		t.Fatalf("Failed to connect to test MQTT: %v", token.Error())
	}
	defer client.Disconnect(250)

	// 3. Act as Home Assistant: adopt the first scanner instance and renew its
	// approval lease so the scanner may publish state and begin scanning.
	var scannerUUID string
	approvalReady := make(chan struct{}, 1)
	client.Subscribe("fortag/discovery/+/instances/+", 1, func(c mqtt.Client, m mqtt.Message) {
		if len(m.Payload()) == 0 {
			return
		}
		var presence struct {
			ScannerUUID string `json:"scanner_uuid"`
			InstanceID  string `json:"instance_id"`
		}
		if err := json.Unmarshal(m.Payload(), &presence); err != nil {
			return
		}
		scannerUUID = presence.ScannerUUID
		approval, _ := json.Marshal(map[string]interface{}{
			"scanner_uuid":  presence.ScannerUUID,
			"instance_id":   presence.InstanceID,
			"approved":      true,
			"lease_seconds": 60,
			"issued_at":     time.Now().UTC().Format(time.RFC3339),
		})
		topic := fmt.Sprintf("fortag/scanners/%s/instances/%s/approval", presence.ScannerUUID, presence.InstanceID)
		c.Publish(topic, 1, false, approval)
		select {
		case approvalReady <- struct{}{}:
		default:
		}
	})

	select {
	case <-approvalReady:
	case <-time.After(20 * time.Second):
		t.Fatal("Timed out waiting for scanner registration")
	}

	// 4. Verify Initial State Publication
	stateChan := make(chan []byte, 8)
	client.Subscribe("fortag/scanners/+/state", 0, func(c mqtt.Client, m mqtt.Message) {
		fmt.Printf("DEBUG: MQTT message received on %s\n", m.Topic())
		select {
		case stateChan <- m.Payload():
		default:
			fmt.Println("DEBUG: Dropping excess state update in test verifier")
		}
	})

	fmt.Println("Waiting for pre-scan database state (timeout: 120s)...")
	select {
	case payload := <-stateChan:
		var state map[string]interface{}
		if err := json.Unmarshal(payload, &state); err != nil {
			t.Fatalf("Invalid JSON in state: %v", err)
		}
		if state["api_version"] != float64(2) {
			t.Fatalf("Unexpected MQTT API version: %v", state["api_version"])
		}
		if state["scanner_version"] != "integration-test" {
			t.Fatalf("Initial state has scanner version %v, want integration-test", state["scanner_version"])
		}
		if state["schema_version"] != float64(2) {
			t.Fatalf("Initial state has schema version %v, want 2", state["schema_version"])
		}
		if state["scanner_uuid"] != scannerUUID {
			t.Fatalf("Initial state scanner UUID = %v, want %s", state["scanner_uuid"], scannerUUID)
		}
		if state["duration"] != "0.00s" {
			t.Fatalf("Initial state was published after scanning; duration = %v", state["duration"])
		}
		fmt.Printf("DEBUG: Received state payload with %d keys\n", len(state))
		fmt.Println("Received pre-scan database state")
	case <-time.After(120 * time.Second):
		// Get container logs before failing
		fmt.Println("CRITICAL: Timeout reached. Capturing scanner logs:")
		logCmd := exec.Command("docker-compose", "-f", "docker-compose.test.yml", "logs", "test-scanner")
		logOut, _ := logCmd.CombinedOutput()
		fmt.Println(string(logOut))
		t.Fatal("Timed out waiting for scanner state")
	}

	// 5. Test Rename Command
	testMAC := "00:00:00:00:00:00" // Mock MAC for localhost if visible, or dummy for test
	// In host mode, localhost might not have a MAC in nmap. We need to find a MAC from the state.

	// (Simplified for this test: we'll just check if we can send a rename and it doesn't crash the scanner)

	fmt.Println("Testing rename command...")
	resultChan := make(chan map[string]interface{}, 8)
	client.Subscribe(fmt.Sprintf("fortag/scanners/%s/command/result", scannerUUID), 1, func(c mqtt.Client, m mqtt.Message) {
		var result map[string]interface{}
		if json.Unmarshal(m.Payload(), &result) == nil {
			resultChan <- result
		}
	})
	renameCommandID := uuid.NewString()
	renamePayload, _ := json.Marshal(map[string]string{
		"command_id": renameCommandID,
		"mac":        testMAC,
		"name":       "Test-Device",
	})
	client.Publish(fmt.Sprintf("fortag/scanners/%s/command/rename", scannerUUID), 1, false, renamePayload)
	for {
		select {
		case result := <-resultChan:
			if result["command_id"] == renameCommandID && result["status"] == "completed" {
				goto renameCompleted
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for rename command result")
		}
	}

renameCompleted:
	// QoS redelivery/retry with the same ID and payload must replay the cached
	// terminal result, while reuse with a different payload must be rejected.
	client.Publish(fmt.Sprintf("fortag/scanners/%s/command/rename", scannerUUID), 1, false, renamePayload)
	select {
	case result := <-resultChan:
		if result["command_id"] != renameCommandID || result["status"] != "completed" {
			t.Fatalf("Unexpected duplicate result: %#v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timed out waiting for cached duplicate result")
	}
	conflictPayload, _ := json.Marshal(map[string]string{
		"command_id": renameCommandID,
		"mac":        testMAC,
		"name":       "Conflicting-Name",
	})
	client.Publish(fmt.Sprintf("fortag/scanners/%s/command/rename", scannerUUID), 1, false, conflictPayload)
	select {
	case result := <-resultChan:
		if result["error_code"] != "command_id_conflict" {
			t.Fatalf("Unexpected command ID conflict result: %#v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timed out waiting for command ID conflict result")
	}

	// Range validation should reject unsafe targets with a useful explanation,
	// while an empty value should safely remove the override and auto-detect.
	invalidRangeID := uuid.NewString()
	invalidRangePayload, _ := json.Marshal(map[string]string{
		"command_id": invalidRangeID,
		"range":      "8.8.8.8",
	})
	client.Publish(fmt.Sprintf("fortag/scanners/%s/command/set_range", scannerUUID), 1, false, invalidRangePayload)
	for {
		select {
		case result := <-resultChan:
			if result["command_id"] != invalidRangeID || result["status"] == "accepted" {
				continue
			}
			if result["status"] != "failed" || !strings.Contains(fmt.Sprint(result["message"]), "outside the supported private IPv4 ranges") {
				t.Fatalf("Unexpected invalid-range result: %#v", result)
			}
			goto invalidRangeRejected
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for invalid-range result")
		}
	}

invalidRangeRejected:
	autoRangeID := uuid.NewString()
	autoRangePayload, _ := json.Marshal(map[string]string{
		"command_id": autoRangeID,
		"range":      "",
	})
	client.Publish(fmt.Sprintf("fortag/scanners/%s/command/set_range", scannerUUID), 1, false, autoRangePayload)
	for {
		select {
		case result := <-resultChan:
			if result["command_id"] == autoRangeID && result["status"] == "completed" {
				goto autoRangeCompleted
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for auto-detect range result")
		}
	}

autoRangeCompleted:

	// 6. Trigger Manual Scan
	fmt.Println("Testing scan_now command...")
	scanPayload, _ := json.Marshal(map[string]string{"command_id": uuid.NewString()})
	client.Publish(fmt.Sprintf("fortag/scanners/%s/command/scan_now", scannerUUID), 1, false, scanPayload)

	// Wait for a second state publication after the manual scan
	select {
	case <-stateChan:
		fmt.Println("Received state after manual scan trigger")
	case <-time.After(20 * time.Second):
		t.Fatal("Timed out waiting for state after manual scan trigger")
	}
}
