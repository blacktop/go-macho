enum MyEnum: String {
    case A = "test"
    case B
    case C
}

struct Name {
    var a: MyEnum
    var b: MyEnum
}

Name(a: .A, b: .B)