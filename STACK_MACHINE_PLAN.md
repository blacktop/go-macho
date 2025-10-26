# Stack Machine Implementation Plan

## Problem Analysis

The ForceBridge symbol `_$ss21_ObjectiveCBridgeableP016_forceBridgeFromA1C_6resulty01_A5CTypeQz_xSgztFZTq` fails with "unsupported mangled sequence starting at 0" because our recursive descent parser's `saveState()`/`restoreState()` mechanism rewinds the parse position after successfully parsing tuple parameters, causing subsequent parse attempts to fail.

##Root Cause

Swift's demangler is fundamentally a **stack machine**, not a recursive descent parser:

1. **Parse operators push nodes** onto a stack (e.g., parsing `01_` pushes a generic param node)
2. **Combinators pop and combine** nodes (e.g., `popTuple()` pops N type nodes and builds a tuple)
3. **No backtracking** - once a node is pushed, the position never rewinds unless parsing fails immediately

Our current approach:
- Uses `saveState()`/`restoreState()` for speculative parsing
- Returns parsed nodes directly from functions
- Rewinds position when a parse path doesn't work out

This works for 99% of cases but breaks in complex scenarios like:
- Function parameter tuples (needs to pop pre-parsed param types)
- Dependent member types with base-first encoding (needs to pop base and assoc type)

## Evidence from CwlDemangle

Key observations from the pure-Swift CwlDemangle implementation:

### 1. Tuple Parsing (`popTuple`)
```swift
mutating func popTuple() throws -> SwiftSymbol {
    var children: [SwiftSymbol] = []
    if pop(kind: .emptyList) == nil {
        var firstElem = false
        repeat {
            firstElem = pop(kind: .firstElementMarker) != nil
            // ... pop identifier for label
            elemChildren.append(try require(pop(kind: .type)))  // ← Pops pre-parsed type!
            children.insert(SwiftSymbol(kind: .tupleElement, children: elemChildren), at: 0)
        } while (!firstElem)
    }
    return SwiftSymbol(typeWithChildKind: .tuple, childChildren: children)
}
```

**Key**: Types are already on the stack before `popTuple()` is called. The function doesn't parse them - it just pops and assembles.

### 2. Dependent Member Type (`Qz` operator)
```swift
case "z":
    let t = try demangleAssociatedTypeSimple(index: getDependentGenericParamType(depth: 0, index: 0))
    substitutions.append(t)
    return t

mutating func demangleAssociatedTypeSimple(index: SwiftSymbol?) throws -> SwiftSymbol {
    let atName = try popAssociatedTypeName()  // ← Pops pre-parsed identifier!
    let gpi = try index.map { SwiftSymbol(kind: .type, child: $0) } ?? require(pop(kind: .type))
    return SwiftSymbol(typeWithChildKind: .dependentMemberType, childChildren: [gpi, atName])
}
```

**Key**: The associated type name (`_ObjectiveCType`) is parsed and pushed onto the stack BEFORE we encounter the `Q` operator. When we see `Qz`, we pop it and combine with the base.

### 3. No Backtracking
CwlDemangle never calls `restoreState()` after successfully pushing a node. Once something is on the stack, it stays there until popped by a combinator.

## Hybrid Implementation Strategy

Rather than rewriting the entire parser, we can add stack-based semantics to the specific areas that need it:

### Phase 1: Infrastructure (✅ DONE)
- [x] Add `nodeStack []*Node` to parser struct
- [x] Add `pushNode()`, `popNode()`, `peekNode()` helpers

### Phase 2: Tuple/Parameter Parsing
1. Modify `parseFunctionType` to parse parameter types and push them onto `nodeStack`
2. Update `parseFunctionInput` to call `popTuple()` which pops pre-pushed types
3. Remove `saveState()`/`restoreState()` from tuple parsing paths

**Critical change**: Instead of:
```go
// Current approach
func (p *parser) parseParameterTuple() (*Node, error) {
    state := p.saveState()
    // ... parse types and return tuple
    if failed {
        p.restoreState(state)  // ← This is the problem!
        return nil, err
    }
    return tuple, nil
}
```

Do this:
```go
// Stack-based approach
func (p *parser) parseParameterTypes() error {
    for {
        typ, err := p.parsePrimaryType()
        if err != nil {
            return err
        }
        p.pushNode(typ)  // ← Push onto stack
        if p.peek() == '_' {
            break
        }
    }
    return nil
}

func (p *parser) popTuple() (*Node, error) {
    // Pop types from stack and build tuple
    var elems []*Node
    for p.peekNode() != nil && p.peekNode().Kind == KindType {
        elems = append([]*Node{p.popNode()}, elems...)
    }
    return NewNode(KindTuple, elems...), nil
}
```

### Phase 3: Dependent Member Types
1. When parsing identifiers in type context, push them onto stack
2. Modify `tryParseDependentMemberWithBase` to pop the identifier from stack
3. Remove backtracking from `Qz` operator handling

**Example**: For `01_A5CTypeQz`:
```go
// Parse '01_' → push generic param "C" onto stack
// Parse 'A5CType' → push identifier "_ObjectiveCType" onto stack  
// See 'Q' → enter archetype demangling
// Read 'z' → pop identifier, create DependentMemberType with implicit base "A" + popped identifier
```

### Phase 4: Testing & Validation
1. Run ForceBridge test - should pass
2. Run full test suite - no regressions
3. Re-enable parity test
4. Update RESEARCH.md with findings

## Implementation Notes

### What to Keep
- Current recursive descent structure for most parsing
- `saveState()`/`restoreState()` for simple backtracking (substitutions, short sequences)
- All existing node types and AST structure

### What to Change
- Function type/tuple parsing: use stack discipline
- Dependent member type parsing: use stack for identifiers
- Remove position rewinds after successful node creation

### What NOT to Change
- Don't rewrite the entire parser as a stack machine
- Don't change the public API
- Don't modify node structure or substitution table

## Timeline Estimate

- **Phase 2 (Tuple Parsing)**: 2-3 hours
  - Understand current tuple parsing flow
  - Refactor to use stack
  - Test basic function types

- **Phase 3 (Dependent Members)**: 1-2 hours
  - Modify identifier pushing
  - Update Qz operator handling
  - Test ForceBridge symbol

- **Phase 4 (Testing)**: 1 hour
  - Run full suite
  - Fix any regressions
  - Update documentation

**Total**: 4-6 hours for a working implementation

## Success Criteria

1. ✅ `TestDemangleObjectiveCBridgeableForceBridge` passes
2. ✅ No regressions in existing 400+ test cases
3. ✅ Parity test re-enabled with ForceBridge as supported
4. ✅ Code is maintainable and well-documented
5. ✅ Performance is not degraded

## Future Considerations

If we encounter more edge cases that require stack discipline:
- Consider full port of CwlDemangle approach
- Would give 1:1 correspondence with Apple's implementation
- Easier to sync with upstream Swift changes
- Estimated at 1-2 days of work

For now, the hybrid approach gives us the best of both worlds:
- Minimal code changes
- Fixes the immediate blocker
- Maintains existing test coverage
- Provides a clear path for future evolution
