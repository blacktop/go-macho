# Diagnosis: Missing DependentMemberType Parsing

## Problem Summary

The pure-Go Swift demangler fails on the symbol:
```
_$ss21_ObjectiveCBridgeableP016_forceBridgeFromA1C_6resulty01_A5CTypeQz_xSgztFZTq
```

Expected output (from Apple's `swift-demangle`):
```
method descriptor for static Swift._ObjectiveCBridgeable._forceBridgeFromObjectiveC(_: A._ObjectiveCType, result: inout A?) -> ()
```

## Root Cause

The parser has a function `tryParseDependentMemberType()` that knows how to parse dependent member types (associated types like `A._ObjectiveCType`), but **this function is never called** from any parsing context.

## Technical Details

### What Should Happen

When parsing the type `01_A5CTypeQz`:

1. **`01_`** → Parse as `DependentGenericParamType(depth=0, index=1)` 
   - This represents generic parameter `A` (the second parameter, index 1)
   - ✅ This currently works via `tryParseDependentGenericParam()`

2. **`A5CTypeQz`** → Parse as `DependentMemberType`
   - `A5CType` = Associated type name (with `A` prefix for internal/private)
   - `Qz` = Operator: `Q` + `z` (base is `DependentGenericParamType(0,0)`)
   - Should create: `DependentMemberType(base=Self, assoc=_ObjectiveCType)`
   - ❌ This FAILS because `tryParseDependentMemberType()` is never called

### Current Parser Flow in `parsePrimaryType()`

```go
func (p *parser) parsePrimaryType() (*Node, error) {
    // 1. Check pending stack
    if len(p.pending) > p.pendingFloor { ... }
    
    // 2. Try dependent generic param (x, z, d<num>, <num>_)
    if node, ok, err := p.tryParseDependentGenericParam(); ... {
        // ✅ This works for '01_' → DependentGenericParamType(0,1)
    }
    
    // 3. Try numeric substitution
    if isDigit(p.peek()) { ... }
    
    // 4. Handle symbolic references (0x01-0x17)
    if b := p.peek(); b >= 0x01 && b <= 0x17 { ... }
    
    // 5. Lookup known types (Si, SS, etc.)
    for l := maxLookup; l >= 1; l-- { ... }
    
    // 6. Try multi-substitution
    if ok, err := p.tryParseMultiSubstitution(); ... }
    
    // 7. Parse standard types
    if node, ok := p.parseStandardType(); ... }
    
    // 8. Try stdlib nominal (s<identifier><kind>)
    if !p.eof() && p.peek() == 's' { ... }
    
    // 9. Parse nominal/identifier (digit-prefixed)
    if c := p.peek(); c >= '0' && c <= '9' { ... }
    
    // 10. Try explicit substitution (S...)
    if node, ok, err := p.tryParseSubstitution(); ... }
    
    // ❌ MISSING: tryParseDependentMemberType()
    
    // 11. Give up
    return nil, fmt.Errorf("unsupported mangled sequence...")
}
```

When the parser encounters `A5CTypeQz`:
- `A` is not a digit → skips step 9
- `A` is not `S` → skips step 10
- No other case matches
- **Returns error: "unsupported mangled sequence"**

### The Existing (But Unused) Function

```go
func (p *parser) tryParseDependentMemberType() (*Node, bool, error) {
    state := p.saveState()
    
    // Parse associated type name (everything before 'Q')
    assoc, err := p.parseAssocTypeNameNode()
    if err != nil {
        p.restoreState(state)
        return nil, false, nil
    }
    
    // Expect 'Q' operator
    if p.eof() || p.peek() != 'Q' {
        p.restoreState(state)
        return nil, false, nil
    }
    p.consume()
    
    // Parse base type indicator
    if p.eof() {
        p.restoreState(state)
        return nil, false, nil
    }
    op := p.consume()
    var base *Node
    switch op {
    case 'z':
        base = newDependentGenericParamNode(0, 0)  // Self
    case 'y':
        gp, ok, err := p.tryParseDependentGenericParam()
        if err != nil || !ok { ... }
        base = gp
    default:
        p.restoreState(state)
        return nil, false, nil
    }
    
    // Build DependentMemberType node
    member := NewNode(KindDependentMemberType, "")
    member.Append(base, assoc)
    p.pushSubstitution(member)
    return member, true, nil
}
```

This function:
- ✅ Correctly reads associated type names (handles `A5CType`)
- ✅ Recognizes `Q` operator
- ✅ Parses `z` and `y` base indicators
- ✅ Builds proper `DependentMemberType` AST nodes
- ❌ **Is never called by any other code**

### Comparison with Swift C++ Implementation

In `OPC/swift-main/lib/Demangling/Demangler.cpp`, the `demangleArchetype()` function handles `Q` operators:

```cpp
case 'Q': return demangleArchetype();  // In main operator switch

NodePointer Demangler::demangleArchetype() {
  switch (nextChar()) {
    case 'x': {
      NodePointer T = demangleAssociatedTypeSimple(nullptr);
      addSubstitution(T);
      return T;
    }
    case 'y': {
      NodePointer T = demangleAssociatedTypeSimple(demangleGenericParamIndex());
      addSubstitution(T);
      return T;
    }
    case 'z': {
      NodePointer T = demangleAssociatedTypeSimple(
          getDependentGenericParamType(0, 0));
      addSubstitution(T);
      return T;
    }
    // ...
  }
}
```

However, the C++ implementation uses a **stack-based approach** where identifiers are pushed onto a stack, then the `Q` operator pops them. The Go implementation is **forward-parsing** instead, which is why `tryParseDependentMemberType` was designed to read the identifier first, then the operator.

## The Fix

Add a call to `tryParseDependentMemberType()` in `parsePrimaryType()`, **before** the final error return:

```go
func (p *parser) parsePrimaryType() (*Node, error) {
    // ... existing checks ...
    
    // Explicit substitution references.
    if node, ok, err := p.tryParseSubstitution(); err != nil {
        return nil, err
    } else if ok {
        return node, nil
    }
    
    // NEW: Try dependent member types (associated types with Q operator)
    if node, ok, err := p.tryParseDependentMemberType(); err != nil {
        return nil, err
    } else if ok {
        return node, nil
    }
    
    // Give up
    if debugEnabled {
        debugf("parsePrimaryType unsupported at pos=%d char=%q remaining=%s\n", ...)
    }
    return nil, fmt.Errorf("unsupported mangled sequence starting at %d", p.pos)
}
```

### Why This Works

1. When the parser encounters `A5CTypeQz`:
   - All previous checks fail (not a digit, not `S`, not a known type, etc.)
   - Parser reaches `tryParseDependentMemberType()`

2. `tryParseDependentMemberType()` internally:
   - Calls `parseAssocTypeNameNode()` → `readAssocIdentifier()`
   - `readAssocIdentifier()` has **fallback logic** to consume everything until `Q`
   - Successfully reads `A5CType`
   - Sees `Q`, consumes it
   - Sees `z`, creates `DependentGenericParamType(0,0)` as base
   - Returns `DependentMemberType` node ✅

3. Parser continues with rest of type signature

## Expected Outcome

After this fix, the symbol should demangle successfully:
- `01_` → `DependentGenericParamType(0,1)` = generic param `A`
- `A5CTypeQz` → `DependentMemberType` = `A._ObjectiveCType`
- Full parameter becomes: `(A._ObjectiveCType, inout A?) -> ()`

## Additional Considerations

### Other Missing 'Q' Operators

The `tryParseDependentMemberType()` currently handles:
- ✅ `Qz` - base is Self (0,0)
- ✅ `Qy` - base is parsed generic param
- ❌ `Qx` - base is nil/popped from stack (not implemented)
- ❌ `QX`, `QY`, `QZ` - compound associated types (not implemented)

These may need to be added in future, but `Qz` and `Qy` are the most common and should handle the immediate failing case.

### Integration Points

The fix should be added to:
- **File**: `internal/swiftdemangle/demangle.go`
- **Function**: `parsePrimaryType()`
- **Location**: After `tryParseSubstitution()`, before final error return
- **Lines**: ~245 (before the final error return)

## Testing

After implementing the fix, verify with:

```bash
cd internal/swiftdemangle
GO_MACHO_SWIFT_ENGINE=purego go test -v -run TestDemangleObjectiveCBridgeableForceBridge
```

Expected: Test passes, symbol demangl successfully.

## Confidence Level

🟢 **HIGH CONFIDENCE** - The diagnosis is conclusive:
1. The required function already exists and is correctly implemented
2. It simply needs to be called from the right location
3. The C++ reference implementation confirms the approach
4. The fix is minimal (3 lines of code)
