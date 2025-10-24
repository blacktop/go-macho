// RUN: %target-typecheck-verify-swift -target %target-cpu-apple-macosx10.15 -swift-version 5

// REQUIRES: OS=macosx

// https://github.com/apple/swift/issues/57240

enum Category {
case first
}

protocol View {}

extension View {
  func test(_ tag: Category) -> some View {
    Image()
  }
}

@resultBuilder struct ViewBuilder {
  static func buildBlock<Content>(_ content: Content) -> Content where Content : View { fatalError() }
}

struct Image : View {
}

struct MyView {
  @ViewBuilder var body: some View {
    let icon: Category! = Category.first // Ok
    Image().test(icon)
  }
}
