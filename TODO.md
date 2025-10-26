# Swift Demangler TODO

- [x] Port Swift symbol/entity grammar from `swift-main/lib/Demangling/Demangler.cpp` (function entities, accessors, initializers, method descriptors).
    - Mirror `Demangler::demangleSymbol` → `demangleEntity` dispatch (functions, vars, accessors, specializations).
    - Add Go equivalents for helper routines (`demangleFunction`, `demangleAccessor`, `demangleInitializer`).
    - Consult `NodePrinter` for formatting cues (e.g., `__allocating_init`, `.getter`).
- [x] Parse argument labels and modifiers (`__allocating_init`, property `getter`/`setter`, coroutine suffixes) so formatted output matches `swift-demangle`.
- [ ] Add node kinds/formatting for full symbols (result arrows, return types, async/throws, method descriptors, witness tables, protocol descriptors, property descriptors).
- [ ] Handle legacy `_T` manglings beyond basic types (old Swift symbol scheme).
- [ ] Expand demangler coverage for specialized contexts: method descriptors, witness table entries, protocol conformances, field/metadata strings.
- [ ] Improve ObjC integration (`So…C` classes, selector names) so symbols referencing Objective-C metadata print consistently.
- [ ] Build a regression corpus comparing against Apple’s `swift-demangle` for representative binaries (functions, accessors, witnesses, descriptors, ObjC bridges); ensure parity in CI.
- [ ] Document the Go implementation with references to Swift ABI sections; add unit tests mirroring `DemangleTests.cpp` cases.
- [ ] Expose clean public API (DemangleSymbol, DemangleType, NormalizeIdentifier with resolver hooks) for downstream tools.
- [ ] Investigate fallback/forward-compat strategy for unknown opcodes (match `swift-demangle` behavior).
- [ ] Implement simplified demangle formatting in the pure-Go engine so `DemangleSimple` matches `swift-demangle -simplified` output and can be parity-tested.
- [ ] Migrate downstream consumers (e.g. `ipsw`) to import `pkg/swift` and delete their local demangler copies once the API stabilizes.
- [x] Auto-generate `internal/swiftdemangle` node kind enums/metadata from `OPC/swift-main/include/swift/Demangling/DemangleNodes.def` (similar to `types/swift` generators) to cover the full ~370-node surface.
- [ ] Port upstream descriptor/async formatting helpers from `ASTDemangler.cpp` / `SwiftDemangle.cpp` so method/property descriptors and ObjC bridge symbols render identically to Apple’s tool.
- [ ] Expand `_T` / legacy mangling coverage by following `OldDemangler.cpp` and adding regression symbols from `test/Demangle` to our parity suite.
