# Swift Type Demangler Integration - Implementation Plan

## Context

The codebase has a pure-Go Swift demangler (`internal/swiftdemangle/`) that already supports:
- Type demangling via `DemangleType()` method
- Symbolic reference resolution via `SymbolicReferenceResolver` interface
- Full type grammar parsing (generics, function types, protocols, etc.)

However, `swift.go`'s metadata parsing uses a legacy helper `makeSymbolicMangledNameStringRef()` that:
- Manually parses symbolic references (control bytes 0x01-0x1F)
- Does ad-hoc demangling with regex and string matching
- Doesn't leverage the robust demangler engine

## Objective

Replace the ad-hoc demangling logic in `makeSymbolicMangledNameStringRef()` with proper calls to the Swift demangler, enabling clean type demangling for metadata records (captures, typeref s, associated types, etc.).

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│ swift.go (Mach-O metadata parsing)                          │
│                                                              │
│  makeSymbolicMangledNameStringRef(addr) {                   │
│    1. Parse symbolic control bytes (0x01-0x1F) + offsets    │
│    2. Build mangled string with embedded refs               │
│    3. Create resolver that can resolve refs → Nodes         │
│    4. Call swiftdemangle.DemangleTypeString(mangled,        │
│         WithResolver(resolver))                             │
│    5. Fall back to legacy logic if demangler fails          │
│  }                                                           │
│                                                              │
│  type machOResolver struct {                                │
│    f *File  // Access to getContextDesc(), etc.             │
│  }                                                           │
│                                                              │
│  func (r *machOResolver) ResolveType(control, payload,      │
│                                      refIndex) (*Node, err) {│
│    // Resolve address → context descriptor → Node           │
│  }                                                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ internal/swiftdemangle/                                      │
│                                                              │
│  DemangleTypeString(mangled, WithResolver(r)) {             │
│    // Parse type with symbolic reference support            │
│  }                                                           │
│                                                              │
│  parser.parseType() {                                       │
│    if control_byte in 0x01-0x1F {                           │
│      node := r.ResolveType(control, payload, refIndex)      │
│      return node                                            │
│    }                                                         │
│  }                                                           │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Stages

### Stage 1: Create SymbolicReferenceResolver for swift.go ✓

**Goal**: Implement a resolver that can translate symbolic references to demangler Nodes

**Tasks**:
1. Add `type machOResolver struct` in `swift.go`
2. Implement `ResolveType(control byte, payload []byte, refIndex int) (*Node, error)` that:
   - Calculates target address from payload (relative offsets or absolute pointers)
   - Calls `getContextDesc()` to read context descriptor
   - Builds appropriate demangler Node (Class, Struct, Protocol, etc.)
   - Handles both direct (0x01) and indirect (0x02) references
3. Handle edge cases (nil pointers, bind names, private symbols)

**Success Criteria**:
- `machOResolver` compiles and implements `SymbolicReferenceResolver` interface
- Basic unit test that resolves a known context descriptor to a Node

**Status**: Not Started

---

### Stage 2: Integrate Demangler into makeSymbolicMangledNameStringRef ✓

**Goal**: Replace ad-hoc demangling with proper demangler calls

**Tasks**:
1. Refactor `makeSymbolicMangledNameStringRef()` to:
   - Keep existing symbolic reference parsing (control bytes → offsets)
   - Create `machOResolver` instance
   - Build raw mangled []byte that includes control bytes
   - Call `swiftdemangle.DemangleTypeString(mangled, swiftdemangle.WithResolver(resolver))`
   - Return demangled result
2. Add fallback to legacy logic if demangler fails (for safety during transition)
3. Add debug logging controlled by `GO_MACHO_SWIFT_DEBUG`

**Success Criteria**:
- Existing tests pass
- Type strings like `_$sSgIegg_` are properly demangled
- No regressions in metadata parsing

**Status**: Not Started

---

### Stage 3: Add Public Type Demangling API (Optional) ✓

**Goal**: Expose type demangling in `pkg/swift` for external consumers

**Tasks**:
1. Add `DemangleType(input string, opts ...Option) (string, error)` to `pkg/swift/api.go`
2. Update `engine` interface to include `DemangleType(string) (string, error)`
3. Implement in both `pureGoEngine` and `darwinEngine`
4. Add unit tests

**Success Criteria**:
- Public API works with type strings
- Both engines (pure-Go and darwin-cgo) support it
- Tests verify output matches `swift-demangle` behavior

**Status**: Not Started

---

### Stage 4: Regression Testing ✓

**Goal**: Ensure type demangling works for all metadata use cases

**Tasks**:
1. Create test fixtures for:
   - Closure captures: `_$sSgIegg_`, `_$sSo7NSErrorCSgIeyBy_`
   - Optional Any: `_$sScA_pSg`
   - Associated types with `Qz`, `Qy_` sequences
   - Metadata source maps
   - Function types with async/throws
2. Add `swift_test.go` with table-driven tests comparing:
   - Raw mangled input
   - Expected demangled output
   - Actual demangler output
3. Use `swiftc` to generate known-good test cases

**Success Criteria**:
- All test fixtures demangle correctly
- Output matches Swift's official `swift-demangle` tool
- Tests pass on both darwin (cgo) and linux (pure-go)

**Status**: Not Started

---

### Stage 5: Documentation & Cleanup ✓

**Goal**: Document the new architecture and remove dead code

**Tasks**:
1. Update `AGENTS.md`:
   - Document the unified demangling architecture
   - Explain when to use symbol vs type entry points
   - Note the resolver pattern for symbolic references
2. Update `RESEARCH.md`:
   - Mark type demangling as implemented
   - Document any remaining grammar gaps
3. Update `TODO.md`:
   - Check off completed items
   - Add any new gaps discovered during implementation
4. Consider removing legacy demangling logic once stable
5. Add code comments explaining the symbolic reference resolution flow

**Success Criteria**:
- Documentation is clear and accurate
- Future maintainers understand the architecture
- No dangling TODOs in code

**Status**: Not Started

---

## Key Technical Details

### Symbolic Reference Resolution

Swift uses control bytes 0x01-0x1F in mangled strings to embed pointers to runtime structures:

```
\x01 + 4-byte-offset  → Direct reference to context descriptor
\x02 + 4-byte-offset  → Indirect reference to context descriptor
\x18-\x1F + 8-bytes   → Absolute 64-bit reference (rare)
```

Our resolver must:
1. Calculate target address: `base_addr + refIndex + 1 + offset`
2. Read context descriptor at target
3. Extract type info (name, module, parent context)
4. Return appropriate Node (KindClass, KindStruct, etc.)

### Type Grammar Already Supported

The demangler already handles:
- ✅ Generic parameters (`x`, `z`, `d<depth><index>`)
- ✅ Dependent member types (`Qz`, `Qy_`)
- ✅ Function types with async/throws (`Yc`, `Kc`)
- ✅ Optionals (`Sg`, `SgXw`)
- ✅ Tuples (`_t`)
- ✅ Bound generics (`yG`)
- ✅ Standard library types (`Si`, `SS`, `Sb`)

### Example Transformation

**Before (ad-hoc)**:
```go
// makeSymbolicMangledNameStringRef manually builds output with regex
if regexp.MustCompile("So[0-9]+").MatchString(part) {
    appendNormalized("_$s" + part)
}
```

**After (proper demangler)**:
```go
// makeSymbolicMangledNameStringRef delegates to demangler
resolver := &machOResolver{f: f}
result, err := swiftdemangle.DemangleTypeString(
    mangledBytes,
    swiftdemangle.WithResolver(resolver),
)
```

## Testing Strategy

1. **Unit tests**: Test `machOResolver` independently with mock context descriptors
2. **Integration tests**: Use real Mach-O binaries with known type payloads
3. **Parity tests**: Compare our output against `swift-demangle` tool
4. **Regression tests**: Ensure no existing functionality breaks

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Demangler doesn't support all type grammar | High | Add fallback to legacy logic; expand grammar incrementally |
| Symbolic reference resolution differs from Swift runtime | Medium | Study Swift C++ sources closely; add extensive logging |
| Performance regression from demangler overhead | Low | Profile and optimize if needed; cache results |
| Breaking existing consumers | High | Keep fallback logic; extensive testing before removal |

## Success Metrics

- [ ] All type strings in metadata demangle correctly
- [ ] Output matches `swift-demangle` tool
- [ ] Tests pass on darwin + linux
- [ ] No regressions in existing functionality
- [ ] Code is cleaner and more maintainable
- [ ] Future grammar additions only need to touch `internal/swiftdemangle/`

## Timeline Estimate

- Stage 1: 4-6 hours (resolver implementation)
- Stage 2: 3-4 hours (integration)
- Stage 3: 2-3 hours (public API, optional)
- Stage 4: 4-6 hours (comprehensive testing)
- Stage 5: 2-3 hours (documentation)

**Total**: ~15-22 hours of focused work

## Next Steps

1. Start with Stage 1: Implement `machOResolver`
2. Add unit tests for resolver
3. Move to Stage 2: Integrate into `makeSymbolicMangledNameStringRef`
4. Iterate with testing and refinement
