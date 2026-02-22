package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryAppendOnlyStore_Append(t *testing.T) {
	store := NewMemoryAppendOnlyStore()

	data := []byte("test data")
	err := store.Append(data)
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Verify data was appended
	allData, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(allData))
	}

	if string(allData[0]) != string(data) {
		t.Errorf("expected %s, got %s", string(data), string(allData[0]))
	}
}

func TestMemoryAppendOnlyStore_MultipleAppends(t *testing.T) {
	store := NewMemoryAppendOnlyStore()

	expected := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	for _, data := range expected {
		if err := store.Append(data); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	allData, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(allData))
	}

	for i, data := range allData {
		if string(data) != string(expected[i]) {
			t.Errorf("entry %d: expected %s, got %s", i, string(expected[i]), string(data))
		}
	}
}

func TestMemoryAppendOnlyStore_GetLastHash(t *testing.T) {
	store := NewMemoryAppendOnlyStore()

	// Empty store should return empty hash
	hash, err := store.GetLastHash()
	if err != nil {
		t.Fatalf("GetLastHash failed: %v", err)
	}
	if hash != "" {
		t.Errorf("expected empty hash, got %s", hash)
	}

	// Append JSON data with checksum field
	data := []byte(`{"checksum":"abc123","value":"test"}`)
	if err := store.Append(data); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	hash, err = store.GetLastHash()
	if err != nil {
		t.Fatalf("GetLastHash failed: %v", err)
	}
	if hash != "abc123" {
		t.Errorf("expected hash abc123, got %s", hash)
	}
}

func TestMemoryAppendOnlyStore_Clear(t *testing.T) {
	store := NewMemoryAppendOnlyStore()

	// Add some data
	store.Append([]byte("test"))

	// Clear
	store.Clear()

	// Verify empty
	allData, _ := store.ReadAll()
	if len(allData) != 0 {
		t.Errorf("expected 0 entries after clear, got %d", len(allData))
	}

	// Verify hash is reset
	hash, _ := store.GetLastHash()
	if hash != "" {
		t.Errorf("expected empty hash after clear, got %s", hash)
	}
}

func TestMemoryAppendOnlyStore_ReadAllCopies(t *testing.T) {
	store := NewMemoryAppendOnlyStore()

	data := []byte("original")
	store.Append(data)

	// Read data
	allData, _ := store.ReadAll()

	// Modify returned data
	allData[0][0] = 'X'

	// Read again and verify original is unchanged
	allData2, _ := store.ReadAll()
	if string(allData2[0]) != "original" {
		t.Error("modifying ReadAll result should not affect stored data")
	}
}

func TestFileAppendOnlyStore_CreateAndAppend(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	store, err := NewFileAppendOnlyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileAppendOnlyStore failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("expected file to be created")
	}

	// Append data
	data := []byte("test entry")
	if err := store.Append(data); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Read back
	allData, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(allData))
	}

	if string(allData[0]) != string(data) {
		t.Errorf("expected %s, got %s", string(data), string(allData[0]))
	}
}

func TestFileAppendOnlyStore_AppendMultiple(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	store, _ := NewFileAppendOnlyStore(filePath)

	entries := [][]byte{
		[]byte("first line"),
		[]byte("second line"),
		[]byte("third line"),
	}

	for _, entry := range entries {
		if err := store.Append(entry); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	allData, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != len(entries) {
		t.Fatalf("expected %d entries, got %d", len(entries), len(allData))
	}

	for i, data := range allData {
		if string(data) != string(entries[i]) {
			t.Errorf("entry %d: expected %s, got %s", i, string(entries[i]), string(data))
		}
	}
}

func TestFileAppendOnlyStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	// Create store and add data
	store1, _ := NewFileAppendOnlyStore(filePath)
	store1.Append([]byte("persistent data"))

	// Create new store instance pointing to same file
	store2, err := NewFileAppendOnlyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileAppendOnlyStore failed: %v", err)
	}

	// Verify data persisted
	allData, err := store2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(allData))
	}

	if string(allData[0]) != "persistent data" {
		t.Errorf("expected 'persistent data', got %s", string(allData[0]))
	}
}

func TestFileAppendOnlyStore_GetEntryCount(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	store, _ := NewFileAppendOnlyStore(filePath)

	// Empty store
	count, err := store.GetEntryCount()
	if err != nil {
		t.Fatalf("GetEntryCount failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}

	// Add entries
	for i := 0; i < 5; i++ {
		store.Append([]byte("entry"))
	}

	count, err = store.GetEntryCount()
	if err != nil {
		t.Fatalf("GetEntryCount failed: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 entries, got %d", count)
	}
}

func TestFileAppendOnlyStore_GetSize(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	store, _ := NewFileAppendOnlyStore(filePath)

	// Empty file
	size, err := store.GetSize()
	if err != nil {
		t.Fatalf("GetSize failed: %v", err)
	}
	if size != 0 {
		t.Errorf("expected size 0, got %d", size)
	}

	// Add data
	store.Append([]byte("test data"))

	size, err = store.GetSize()
	if err != nil {
		t.Fatalf("GetSize failed: %v", err)
	}

	// Size should be approximately len("test data") + 1 (newline)
	// We allow some flexibility for encoding
	if size < 9 {
		t.Errorf("expected size >= 9, got %d", size)
	}
}

func TestFileAppendOnlyStore_Compact(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")
	compactPath := filepath.Join(tmpDir, "audit.compact.log")

	store, _ := NewFileAppendOnlyStore(filePath)

	// Add entries
	entries := [][]byte{
		[]byte("entry1"),
		[]byte("entry2"),
		[]byte("entry3"),
	}

	for _, entry := range entries {
		store.Append(entry)
	}

	// Compact
	if err := store.Compact(compactPath); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}

	// Verify compacted file exists
	if _, err := os.Stat(compactPath); os.IsNotExist(err) {
		t.Error("expected compacted file to exist")
	}

	// Open compacted store and verify data
	compactStore, err := NewFileAppendOnlyStore(compactPath)
	if err != nil {
		t.Fatalf("NewFileAppendOnlyStore failed: %v", err)
	}

	allData, err := compactStore.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != len(entries) {
		t.Fatalf("expected %d entries, got %d", len(entries), len(allData))
	}

	for i, data := range allData {
		if string(data) != string(entries[i]) {
			t.Errorf("entry %d: expected %s, got %s", i, string(entries[i]), string(data))
		}
	}
}

func TestFileAppendOnlyStore_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	// Create file with existing data
	originalData := []byte("existing data")
	os.WriteFile(filePath, append(originalData, '\n'), 0644)

	// Open store
	store, err := NewFileAppendOnlyStore(filePath)
	if err != nil {
		t.Fatalf("NewFileAppendOnlyStore failed: %v", err)
	}

	// Verify existing data is readable
	allData, err := store.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(allData) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(allData))
	}

	if string(allData[0]) != string(originalData) {
		t.Errorf("expected %s, got %s", string(originalData), string(allData[0]))
	}

	// Add new data
	newData := []byte("new data")
	store.Append(newData)

	allData, _ = store.ReadAll()
	if len(allData) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(allData))
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected [][]byte
	}{
		{
			name:     "single line",
			input:    []byte("line1"),
			expected: [][]byte{[]byte("line1")},
		},
		{
			name:     "multiple lines",
			input:    []byte("line1\nline2\nline3"),
			expected: [][]byte{[]byte("line1"), []byte("line2"), []byte("line3")},
		},
		{
			name:     "trailing newline",
			input:    []byte("line1\nline2\n"),
			expected: [][]byte{[]byte("line1"), []byte("line2")},
		},
		{
			name:     "empty input",
			input:    []byte(""),
			expected: [][]byte{},
		},
		{
			name:     "only newlines",
			input:    []byte("\n\n"),
			expected: [][]byte{[]byte(""), []byte("")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitLines(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d lines, got %d", len(tt.expected), len(result))
			}
			for i, line := range result {
				if string(line) != string(tt.expected[i]) {
					t.Errorf("line %d: expected %s, got %s", i, string(tt.expected[i]), string(line))
				}
			}
		})
	}
}

func TestAppendOnlyStoreInterface(t *testing.T) {
	// Verify both implementations satisfy the interface
	var _ AppendOnlyStore = (*MemoryAppendOnlyStore)(nil)
	var _ AppendOnlyStore = (*FileAppendOnlyStore)(nil)
}

func TestConcurrentAppends(t *testing.T) {
	store := NewMemoryAppendOnlyStore()

	// Test concurrent appends
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			data := []byte(string(rune('A' + n)))
			store.Append(data)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all entries were added
	allData, _ := store.ReadAll()
	if len(allData) != 10 {
		t.Errorf("expected 10 entries, got %d", len(allData))
	}
}
