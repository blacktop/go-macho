//
//  CwlDemangleAdditionalTests.swift
//  CwlDemangleTests
//
//  Created by Matt Gallagher on 15/2/20.
//  Copyright © 2020 Matt Gallagher. All rights reserved.
//

#if SWIFT_PACKAGE
@testable import CwlDemangle
#endif

import Foundation
import XCTest

class CwlDemangleAdditionalTests: XCTestCase {
	func testUnicodeProblem() {
		let input = "_T0s14StringProtocolP10FoundationSS5IndexVADRtzrlE10componentsSaySSGqd__11separatedBy_tsAARd__lF"
		let output = "(extension in Foundation):Swift.StringProtocol< where A.Index == Swift.String.Index>.components<A where A1: Swift.StringProtocol>(separatedBy: A1) -> [Swift.String]"
		do {
			let parsed = try parseMangledSwiftSymbol(input)
			let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
			XCTAssert(result == output, "Failed to demangle \(input). Got \(result), expected \(output)")
		} catch {
			XCTFail("Failed to demangle \(input). Got \(error), expected \(output)")
		}
	}
	func test_T011CryptoSwift3AESC0017sBoxstorage_wEEFc33_2FA9B7ACC72B80C564A140F8079C9914LLSays6UInt32VGSgvpWvd() {
		let input = "_T011CryptoSwift3AESC0017sBoxstorage_wEEFc33_2FA9B7ACC72B80C564A140F8079C9914LLSays6UInt32VGSgvpWvd"
		let output = "direct field offset for CryptoSwift.AES.(sBox.storage in _2FA9B7ACC72B80C564A140F8079C9914) : [Swift.UInt32]?"
		do {
			let parsed = try parseMangledSwiftSymbol(input)
			let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
			XCTAssert(result == output, "Failed to demangle \(input). Got \(result), expected \(output)")
		} catch {
			XCTFail("Failed to demangle \(input). Got \(error), expected \(output)")
		}
	}
	
	func testLargeMethodNameIssueWithGraphZahl() {
		let input = "$s11rentXserver8RentXApiO5QueryC13createBooking6userId03carI09startDate03endL03lat4long16bookingConfirmed5price8discount5isNew3NIO15EventLoopFutureCyAA0G0CG10Foundation4UUIDV_AyW0L0VA_S2fSbS2dSbtF"
		
		let output = "rentXserver.RentXApi.Query.createBooking(userId: Foundation.UUID, carId: Foundation.UUID, startDate: Foundation.Date, endDate: Foundation.Date, lat: Swift.Float, long: Swift.Float, bookingConfirmed: Swift.Bool, price: Swift.Double, discount: Swift.Double, isNew: Swift.Bool) -> NIO.EventLoopFuture<rentXserver.Booking>"
		
		do {
			let parsed = try parseMangledSwiftSymbol(input)
			let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
			XCTAssert(result == output, "Failed to demangle \(input). Got \(result), expected \(output)")
		} catch {
			XCTFail("Failed to demangle \(input). Got \(error), expected \(output)")
		}
	}
	
	func testIssue16() {
		let input = "$s20EagleFilerSwiftTests07EFErrorD0C00141$s20EagleFilerSwiftTests07EFErrorD0C20nsErrorRoundTripping4TestfMp_62__$test_container__function__funcnsErrorRoundTripping__throwsfMu__FnFBDlO7__testsSay7Testing4TestVGvgZyyYaYbKcfu_TQ0_"
		let output = "(1) await resume partial function for implicit closure #1 @Sendable () async throws -> () in static EagleFilerSwiftTests.EFErrorTests.$s20EagleFilerSwiftTests07EFErrorD0C20nsErrorRoundTripping4TestfMp_62__🟠$test_container__function__funcnsErrorRoundTripping__throwsfMu_.__tests.getter : [Testing.Test]"
		do {
			let parsed = try parseMangledSwiftSymbol(input)
			let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
			XCTAssert(result == output, "Failed to demangle \(input). Got\n\n\(result)\n, expected\n\n\(output)")
		} catch {
			XCTFail("Failed to demangle \(input). Got \(error)")
		}
	}
    
    func testIssue18() async throws {
		 // This issue requires testing on not-the-main thread.
		 try await Task.detached {
			 let symbol = try parseMangledSwiftSymbol("_$s7SwiftUI17_Rotation3DEffectV14animatableDataAA14AnimatablePairVySdAFy12CoreGraphics7CGFloatVAFyAiFyAiFyAFyA2IGAJGGGGGvpMV")
			 print(symbol.description)
		 }.value
    }
    
    func testIssue19() throws {
        let input = "_$s10AppIntents19CameraCaptureIntentP0A7ContextAC_SETn"
        let output = "associated conformance descriptor for AppIntents.CameraCaptureIntent.AppIntents.CameraCaptureIntent.AppContext: Swift.Encodable"
        do {
            let parsed = try parseMangledSwiftSymbol(input)
            let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
            XCTAssert(result == output, "Failed to demangle \(input). Got\n\n\(result)\n, expected\n\n\(output)")
        } catch {
            XCTFail("Failed to demangle \(input). Got \(error)")
        }
    }
	
	func testIssue20() throws {
		let input = "_$s10AppIntents13IndexedEntityPAA0aD0Tb"
		let output = "base conformance descriptor for AppIntents.IndexedEntity: AppIntents.AppEntity"
		do {
			 let parsed = try parseMangledSwiftSymbol(input)
			 let result = parsed.print(using: SymbolPrintOptions.default.union(.synthesizeSugarOnTypes))
			 XCTAssert(result == output, "Failed to demangle \(input). Got\n\n\(result)\n, expected\n\n\(output)")
		} catch {
			 XCTFail("Failed to demangle \(input). Got \(error)")
		}
	}
}
