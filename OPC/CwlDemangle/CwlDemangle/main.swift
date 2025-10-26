//
//  main.swift
//  CwlDemangle
//
//  Created by Matt Gallagher on 2016/04/30.
//  Copyright © 2016 Matt Gallagher. All rights reserved.
//
//  Licensed under Apache License v2.0 with Runtime Library Exception
//
//  See http://swift.org/LICENSE.txt for license information
//  See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
//

#if SWIFT_PACKAGE
	import CwlDemangle
#endif
import Foundation

//
// This function shows suggested usage of the mangled symbol parser and printer.
//
func demangle(input: String, expectedOutput: String) {
	do {
		// Parse the symbol
		let swiftSymbol = try parseMangledSwiftSymbol(input)
		
		// Print the symbol to a string (the .synthesizeSugarOnTypes option i
		// specified to match those used to generate the "manglings.txt" file). 
		let result = swiftSymbol.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
		
		// Check we got the expected result
		if result != expectedOutput {
			print("Failed to demangle:\n   \(input)\nGot:\n   \(result)\nexpected:\n   \(expectedOutput)\n")
		} else {
			print("Successfully parsed and printed:\n   \(input)\nto:\n   \(expectedOutput)\n")
		}
	} catch {
		// If parsing fails, the standard approach used by the `swift-demangle`
		// tool is to copy the input to the output. We check if input equals
		// output to see if a failure was expected.
		if input != expectedOutput {
			print("Failed to demangle:\n   \(input)\nRaised:\n   \(error)\nexpected:\n   \(expectedOutput)\n")
		} else {
			print("As expected, \(input) failed to parse.\n")
		}
	}
}

struct Mangling {
	let input: String
	let output: String
	
	// The "manglings.txt" file contains some prefixes and metadata that are not
	// handled by the actual parser and printer so they're stripped, here.
	init(input: String, output: String) {
		if input.starts(with: "__") {
			self.input = String(input.dropFirst())
		} else {
			self.input = input
		}
		if output.starts(with: "{"), let endBrace = output.firstIndex(where: { $0 == "}" }), let space = output.index(endBrace, offsetBy: 2, limitedBy: output.endIndex) {
			self.output = String(output[space...])
		} else {
			self.output = output
		}
	}
}

// The "manglings.txt" file is copied from "swift/test/Demangle/inputs/manglings.txt"
// in the Swift github repostory.
func readManglings() -> [Mangling] {
	do {
		let input = try String(contentsOfFile: "./CwlDemangle_CwlDemangleTool.bundle/Contents/Resources/manglings.txt", encoding: String.Encoding.utf8)
		let lines = input.components(separatedBy: "\n").filter { !$0.isEmpty }
		return try lines.compactMap { i -> Mangling? in
			let components = i.components(separatedBy: " ---> ")
			if components.count != 2 {
				if i.components(separatedBy: " --> ").count == 2 || i.components(separatedBy: " -> ").count >= 2 {
					return nil
				}
				enum InputError: Error { case unableToSplitLine(String) }
				throw InputError.unableToSplitLine(i)
			}
			return Mangling(input: components[0].trimmingCharacters(in: .whitespaces), output: components[1].trimmingCharacters(in: .whitespaces))
		}
	} catch {
		fatalError("Error reading manglings.txt file: \(error)")
	}
}

func demanglePerformanceTest(_ manglings: [Mangling]) {
	for mangling in manglings {
		for _ in 0..<10000 {
			_ = try? parseMangledSwiftSymbol(mangling.input).description
		}
	}
}

// Generate XCTest cases from the manglings.txt file.
func generateTestCases(_ manglings: [Mangling]) {
	var existing = Set<String>()
	for mangling in manglings {
		guard existing.contains(mangling.input) == false else { continue }
		existing.insert(mangling.input)
		if mangling.input == mangling.output {
			print ("""
				func test\(mangling.input.replacingOccurrences(of: ".", with: "dot").replacingOccurrences(of: "@", with: "at"))() {
					let input = "\(mangling.input)"
					do {
						let demangled = try parseMangledSwiftSymbol(input).description
						XCTFail("Invalid input \\(input) should throw an error, instead returned \\(demangled)")
					} catch {
					}
				}
				""")
		} else {
			print ("""
				func test\(mangling.input.replacingOccurrences(of: ".", with: "dot").replacingOccurrences(of: "@", with: "at"))() {
					let input = "\(mangling.input)"
					let output = "\(mangling.output.replacingOccurrences(of: "\"", with: "\\\""))"
					do {
						let parsed = try parseMangledSwiftSymbol(input)
						let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
						XCTAssert(result == output, "Failed to demangle \\(input).\\nGot\\n    \\(result)\\nexpected\\n    \\(output)")
					} catch {
						XCTFail("Failed to demangle \\(input). Got \\(error), expected \\(output)")
					}
				}
				""")
		}
	}
}

// Step 1: read the file
let manglings = readManglings()

#if true
	// Step 2a: generate XCTest cases
	generateTestCases(manglings)
#elseif !PERFORMANCE_TEST
	// Step 2b: demangle the contains of the file (default)
	for mangling in manglings {
		demangle(input: mangling.input, expectedOutput: mangling.output)
	}
#else
	// Step 2c: run all of the test cases 10,000 times so it's easier to profile
	demanglePerformanceTest(manglings)
#endif

