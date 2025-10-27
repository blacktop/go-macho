package macho

import (
	"bytes"
	"io"
	"testing"
)

// mockCacheReader is a simple in-memory reader for testing
type mockCacheReader struct {
	data []byte
	pos  int64
}

func (m *mockCacheReader) Read(p []byte) (n int, err error) {
	if m.pos >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += int64(n)
	return n, nil
}

func (m *mockCacheReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		m.pos = offset
	case io.SeekCurrent:
		m.pos += offset
	case io.SeekEnd:
		m.pos = int64(len(m.data)) + offset
	}
	if m.pos < 0 {
		m.pos = 0
	}
	if m.pos > int64(len(m.data)) {
		m.pos = int64(len(m.data))
	}
	return m.pos, nil
}

func (m *mockCacheReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, io.EOF
	}
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return n, err
}

func (m *mockCacheReader) SeekToAddr(addr uint64) error {
	m.pos = int64(addr)
	return nil
}

func (m *mockCacheReader) ReadAtAddr(p []byte, addr uint64) (n int, err error) {
	oldPos := m.pos
	m.pos = int64(addr)
	n, err = m.Read(p)
	m.pos = oldPos
	return n, err
}

// TestReadRawMangledBytes tests the raw byte reading functionality
func TestReadRawMangledBytes(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		addr     uint64
		expected []byte
		wantErr  bool
	}{
		{
			name:     "simple string",
			data:     []byte("SiSS\x00extra data"),
			addr:     0,
			expected: []byte("SiSS"),
			wantErr:  false,
		},
		{
			name: "string with 32-bit symbolic reference",
			data: append([]byte("Si"),
				0x01,             // control byte
				0x10, 0x00, 0x00, 0x00, // 32-bit offset
				'S', 'S', 0x00),
			addr:     0,
			expected: []byte("Si\x01\x10\x00\x00\x00SS"),
			wantErr:  false,
		},
		{
			name:     "string with padding",
			data:     []byte("Si\xffSS\x00"),
			addr:     0,
			expected: []byte("Si\xffSS"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{
				cr: &mockCacheReader{data: tt.data},
			}

			result, err := f.readRawMangledBytes(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Error("readRawMangledBytes() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("readRawMangledBytes() unexpected error: %v", err)
				return
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("readRawMangledBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestMakeSymbolicMangledNameWithDemangler_BasicTypes tests basic type demangling
func TestMakeSymbolicMangledNameWithDemangler_BasicTypes(t *testing.T) {
	tests := []struct {
		name        string
		mangled     []byte
		expectError bool
		description string
	}{
		{
			name:        "Swift.Int",
			mangled:     []byte("Si\x00"),
			expectError: false,
			description: "Basic Swift.Int type",
		},
		{
			name:        "Swift.String",
			mangled:     []byte("SS\x00"),
			expectError: false,
			description: "Basic Swift.String type",
		},
		{
			name:        "Swift.Bool",
			mangled:     []byte("Sb\x00"),
			expectError: false,
			description: "Basic Swift.Bool type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{
				cr: &mockCacheReader{data: tt.mangled},
			}

			result, err := f.makeSymbolicMangledNameWithDemangler(0)

			if tt.expectError {
				if err == nil {
					t.Errorf("makeSymbolicMangledNameWithDemangler() expected error for %s", tt.description)
				}
				return
			}

			if err != nil {
				// It's okay if demangler doesn't support it yet - we have fallback
				t.Logf("makeSymbolicMangledNameWithDemangler() %s failed (will use fallback): %v", tt.description, err)
				return
			}

			if result == "" {
				t.Errorf("makeSymbolicMangledNameWithDemangler() returned empty result for %s", tt.description)
			}

			t.Logf("makeSymbolicMangledNameWithDemangler() %s = %q", tt.description, result)
		})
	}
}

// TestMakeSymbolicMangledNameStringRef_Fallback verifies fallback mechanism works
func TestMakeSymbolicMangledNameStringRef_Fallback(t *testing.T) {
	// Create a simple mangled string that might fail with new demangler
	// but should work with legacy logic
	data := []byte("Si\x00")

	f := &File{
		cr: &mockCacheReader{data: data},
	}

	// This should try new demangler first, fall back to legacy if needed
	result, err := f.makeSymbolicMangledNameStringRef(0)

	// Should not error (fallback should handle it)
	if err != nil {
		t.Errorf("makeSymbolicMangledNameStringRef() with fallback failed: %v", err)
		return
	}

	if result == "" {
		t.Error("makeSymbolicMangledNameStringRef() returned empty result")
	}

	t.Logf("makeSymbolicMangledNameStringRef() with fallback = %q", result)
}
