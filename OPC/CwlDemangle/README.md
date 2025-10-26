# CwlDemangle

A translation (line-by-line in many cases) of Swift's [Demangler.cpp](https://github.com/apple/swift/blob/master/lib/Demangling/Demangler.cpp) into Swift.

## License note

I usually place my code under an ISC-style license but since this project is derived from the Swift project, it is covered by that project's [Apache License 2.0 with runtime library exception](https://github.com/apple/swift/blob/master/LICENSE.txt).

## Usage
	
Parse a `String` containing a mangled Swift symbol with the `parseMangledSwiftSymbol` function:

```swift
let swiftSymbol = try parseMangledSwiftSymbol(input)
```
		
Print the symbol to a string with `description` (to get the `.default` printing options) or use the `print(using:)` function, e.g.:

```swift
let result = swiftSymbol.print(using:
   SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
```

## Article

Read more about this project in the associated article on Cocoa with Love: [Comparing Swift to C++ for parsing](https://www.cocoawithlove.com/blog/2016/05/01/swift-name-demangling.html)
