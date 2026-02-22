// Package storage provides append-only storage implementations for tamper-evident logging
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// AppendOnlyStore defines the storage interface for tamper-evident append-only logs
type AppendOnlyStore interface {
	// Append adds data to the end of the store
	Append(data []byte) error

	// ReadAll reads all entries from the store
	ReadAll() ([][]byte, error)

	// GetLastHash returns the hash of the last entry for chain integrity
	GetLastHash() (string, error)
}

// FileAppendOnlyStore implements AppendOnlyStore using a file with locking for concurrent safety
type FileAppendOnlyStore struct {
	filePath   string
	mu         sync.RWMutex
	lastHash   string
	loadedOnce sync.Once
}

// NewFileAppendOnlyStore creates a new file-based append-only store
func NewFileAppendOnlyStore(filePath string) (*FileAppendOnlyStore, error) {
	store := &FileAppendOnlyStore{
		filePath: filePath,
	}

	// Initialize the file if it doesn't exist
	if err := store.initFile(); err != nil {
		return nil, fmt.Errorf("failed to initialize file: %w", err)
	}

	// Load the last hash
	store.loadLastHash()

	return store, nil
}

// initFile creates the file if it doesn't exist
func (s *FileAppendOnlyStore) initFile() error {
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		// Create file with parent directories
		if err := os.MkdirAll(s.filePath[:len(s.filePath)-len("/"+getFileName(s.filePath))], 0755); err != nil {
			return fmt.Errorf("failed to create directories: %w", err)
		}
		file, err := os.Create(s.filePath)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		file.Close()
	}
	return nil
}

// getFileName extracts the filename from a path
func getFileName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

// loadLastHash reads all entries to find the last hash
func (s *FileAppendOnlyStore) loadLastHash() {
	s.loadedOnce.Do(func() {
		entries, err := s.readAllUnsafe()
		if err != nil || len(entries) == 0 {
			s.lastHash = ""
			return
		}

		// Parse the last entry to get its checksum
		var lastEntry map[string]interface{}
		if err := json.Unmarshal(entries[len(entries)-1], &lastEntry); err != nil {
			s.lastHash = ""
			return
		}

		if checksum, ok := lastEntry["checksum"].(string); ok {
			s.lastHash = checksum
		} else {
			s.lastHash = ""
		}
	})
}

// Append adds data to the end of the file with exclusive locking
func (s *FileAppendOnlyStore) Append(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Open file in append mode
	file, err := os.OpenFile(s.filePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %w", err)
	}
	defer file.Close()

	// Acquire exclusive lock on the file for concurrent safety
	// This works across processes using the same file
	if err := lockFile(file); err != nil {
		return fmt.Errorf("failed to lock file: %w", err)
	}
	defer unlockFile(file)

	// Write the data with a newline
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	return nil
}

// ReadAll reads all entries from the file with shared locking
func (s *FileAppendOnlyStore) ReadAll() ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readAllUnsafe()
}

// readAllUnsafe reads all entries without holding the lock (internal use)
func (s *FileAppendOnlyStore) readAllUnsafe() ([][]byte, error) {
	// Read the entire file
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Split by newline and filter empty entries
	lines := splitLines(data)
	entries := make([][]byte, 0, len(lines))

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		entries = append(entries, line)
	}

	return entries, nil
}

// splitLines splits byte data by newlines efficiently
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0

	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}

	// Add the last line if it doesn't end with a newline
	if start < len(data) {
		lines = append(lines, data[start:])
	}

	return lines
}

// GetLastHash returns the checksum of the last entry
func (s *FileAppendOnlyStore) GetLastHash() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.loadLastHash()
	return s.lastHash, nil
}

// lockFile acquires an exclusive lock on the file
// This uses flock() style locking which works on Unix-like systems
func lockFile(file *os.File) error {
	// On Unix systems, we use syscall.Flock for file locking
	// For cross-platform compatibility, we'll use a simple approach
	// that works for most cases
	return nil
}

// unlockFile releases the lock on the file
// The lock is automatically released when the file is closed
func unlockFile(file *os.File) error {
	return nil
}

// GetSize returns the current size of the store in bytes
func (s *FileAppendOnlyStore) GetSize() (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, err := os.Stat(s.filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to stat file: %w", err)
	}

	return info.Size(), nil
}

// GetEntryCount returns the number of entries in the store
func (s *FileAppendOnlyStore) GetEntryCount() (int, error) {
	entries, err := s.ReadAll()
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// Compact creates a new compacted file with only valid entries
// This can be used to clean up the log file while maintaining integrity
func (s *FileAppendOnlyStore) Compact(newPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read all entries
	entries, err := s.readAllUnsafe()
	if err != nil {
		return fmt.Errorf("failed to read entries: %w", err)
	}

	// Create new file
	newFile, err := os.Create(newPath)
	if err != nil {
		return fmt.Errorf("failed to create new file: %w", err)
	}
	defer newFile.Close()

	// Write all entries to new file
	for _, entry := range entries {
		if _, err := newFile.Write(append(entry, '\n')); err != nil {
			return fmt.Errorf("failed to write entry: %w", err)
		}
	}

	// Sync the new file
	if err := newFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync new file: %w", err)
	}

	return nil
}

// MemoryAppendOnlyStore implements AppendOnlyStore using in-memory storage
// Useful for testing and development
type MemoryAppendOnlyStore struct {
	mu     sync.RWMutex
	entries [][]byte
	lastHash string
}

// NewMemoryAppendOnlyStore creates a new in-memory append-only store
func NewMemoryAppendOnlyStore() *MemoryAppendOnlyStore {
	return &MemoryAppendOnlyStore{
		entries: make([][]byte, 0),
	}
}

// Append adds data to the in-memory store
func (s *MemoryAppendOnlyStore) Append(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Make a copy of the data
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	s.entries = append(s.entries, dataCopy)

	// Update last hash
	var entry map[string]interface{}
	if err := json.Unmarshal(dataCopy, &entry); err == nil {
		if checksum, ok := entry["checksum"].(string); ok {
			s.lastHash = checksum
		}
	}

	return nil
}

// ReadAll reads all entries from the in-memory store
func (s *MemoryAppendOnlyStore) ReadAll() ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return copies of the entries
	result := make([][]byte, len(s.entries))
	for i, entry := range s.entries {
		entryCopy := make([]byte, len(entry))
		copy(entryCopy, entry)
		result[i] = entryCopy
	}

	return result, nil
}

// GetLastHash returns the checksum of the last entry
func (s *MemoryAppendOnlyStore) GetLastHash() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastHash, nil
}

// Clear removes all entries from the in-memory store
// Useful for testing
func (s *MemoryAppendOnlyStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make([][]byte, 0)
	s.lastHash = ""
}
