// RUN: %target-typecheck-verify-swift -target %target-cpu-apple-macosx10.15 -swift-version 5

// REQUIRES: objc_interop
// REQUIRES: OS=macosx

// https://github.com/apple/swift/issues/56479

import SwiftUI
import Foundation

struct ContentView: View {
  @State private var date = Date()

  var body: some View {
    Group {
      DatePicker("Enter a date", selection: $date, displayedComponents: .date, in: Date())
      // expected-error@-1 {{argument 'in' must precede argument 'displayedComponents'}} {{78-90=}} {{52-52=in: Date(), }}
      DatePicker("Enter a date", selection: $date, displayedComponents: .date, in: Date() ... Date().addingTimeInterval(100))
    }
  }
}
