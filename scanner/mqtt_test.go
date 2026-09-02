package main

import (
	"fmt"
	"testing"
	"time"
)

func TestPruneCommandCacheExpiresAndBoundsEntries(t *testing.T) {
	now := time.Now().UTC()
	client := &MQTTClient{commandCache: map[string]commandCacheEntry{
		"expired": {receivedAt: now.Add(-commandCacheTTL)},
		"recent":  {receivedAt: now.Add(-time.Minute)},
	}}
	client.pruneCommandCache(now)
	if _, ok := client.commandCache["expired"]; ok {
		t.Fatal("expired command was retained")
	}
	if _, ok := client.commandCache["recent"]; !ok {
		t.Fatal("recent command was removed")
	}

	client.commandCache = make(map[string]commandCacheEntry, commandCacheLimit)
	for i := 0; i < commandCacheLimit; i++ {
		client.commandCache[fmt.Sprintf("command-%04d", i)] = commandCacheEntry{
			receivedAt: now.Add(time.Duration(i) * time.Second),
		}
	}
	client.pruneCommandCache(now.Add(commandCacheTTL - time.Hour))
	if len(client.commandCache) != commandCacheLimit-1 {
		t.Fatalf("cache size = %d, want %d", len(client.commandCache), commandCacheLimit-1)
	}
	if _, ok := client.commandCache["command-0000"]; ok {
		t.Fatal("oldest command was not evicted")
	}
}
