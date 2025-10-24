import Foundation

public struct Outer {
  public struct Inner {
    public let value: Int
  }

  public let inner: Inner
  public let tuple: (Int, String)
  public let maybe: Inner?
}

public class DemoClass {
  public var numbers: [Int]
  public init(numbers: [Int]) {
    self.numbers = numbers
  }
}

public protocol DemoProtocol {
  associatedtype Value
}

public struct Conformer: DemoProtocol {
  public typealias Value = Outer.Inner
}

public actor Counter {
  public var value: Int
  public init(value: Int) {
    self.value = value
  }
  public func increment() -> Int {
    value += 1
    return value
  }
}

public struct ExistentialHolder {
  public var value: any DemoProtocol
  public init(value: any DemoProtocol) {
    self.value = value
  }
}

public func combine(_ lhs: Outer.Inner, _ rhs: Outer.Inner) async throws -> Outer.Inner {
  return lhs
}

public func wrap<T>(_ value: T) -> T {
  value
}

public func takesProtocol(_ value: any DemoProtocol) {
  _ = value
}

public func makeTupleClosure() -> ((Outer.Inner, Outer.Inner) -> Outer.Inner) {
  { lhs, rhs in lhs }
}

public func makeOpaque() -> some DemoProtocol {
  Conformer()
}

public struct GenericHolder<T> {
  public let value: T
  public init(value: T) { self.value = value }
}

public enum Payload {
  case simple(Outer.Inner)
  case complex((Int, String)?)
}

@objcMembers
public class ObjCBridgeClass: NSObject {
  public var label: String
  public var payload: Outer.Inner

  public init(label: String, payload: Outer.Inner) {
    self.label = label
    self.payload = payload
  }

  public func updateLabel(with value: Int) -> String {
    label = "Value: \(value)"
    return label
  }

  public func payloadValue() -> Int {
    payload.value
  }
}
