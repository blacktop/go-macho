package swift

var MangledKnownTypeKind = map[string]string{
	"A": "Swift.AutoreleasingUnsafeMutablePointer",
	"a": "Swift.Array",
	"B": "Swift.BinaryFloatingPoint",
	"b": "Swift.Bool",
	"c": "MangledKnownTypeKind2",
	"D": "Swift.Dictionary",
	"d": "Swift.Float64",
	"E": "Swift.Encodable",
	"e": "Swift.Decodable",
	"F": "Swift.FloatingPoint",
	"f": "Swift.Float32",
	"G": "Swift.RandomNumberGenerator",
	"H": "Swift.Hashable",
	"h": "Swift.Set",
	"I": "Swift.DefaultIndices",
	"i": "Swift.Int",
	"J": "Swift.Character",
	"j": "Swift.Numeric",
	"K": "Swift.BidirectionalCollection",
	"k": "Swift.RandomAccessCollection",
	"L": "Swift.Comparable",
	"l": "Swift.Collection",
	"M": "Swift.MutableCollection",
	"m": "Swift.RangeReplaceableCollection",
	"N": "Swift.ClosedRange",
	"n": "Swift.Range",
	"O": "Swift.ObjectIdentifier",
	"P": "Swift.UnsafePointer",
	"p": "Swift.UnsafeMutablePointer",
	"Q": "Swift.Equatable",
	"q": "Swift.Optional",
	"R": "Swift.UnsafeBufferPointer",
	"r": "Swift.UnsafeMutableBufferPointer",
	"S": "Swift.String",
	"s": "Swift.Substring",
	"T": "Swift.Sequence",
	"t": "Swift.IteratorProtocol",
	"U": "Swift.UnsignedInteger",
	"u": "Swift.UInt",
	"V": "Swift.UnsafeRawPointer",
	"v": "Swift.UnsafeMutableRawPointer",
	"W": "Swift.UnsafeRawBufferPointer",
	"w": "Swift.UnsafeMutableRawBufferPointer",
	"X": "Swift.RangeExpression",
	"x": "Swift.Strideable",
	"Y": "Swift.RawRepresentable",
	"y": "Swift.StringProtocol",
	"Z": "Swift.SignedInteger",
	"z": "Swift.BinaryInteger",
}

var MangledKnownTypeKind2 = map[string]string{
	"A": "Swift.Actor",
	"C": "Swift.CheckedContinuation",
	"c": "Swift.UnsafeContinuation",
	"E": "Swift.CancellationError",
	"e": "Swift.UnownedSerialExecutor",
	"F": "Swift.Executor",
	"f": "Swift.SerialExecutor",
	"G": "Swift.TaskGroup",
	"g": "Swift.ThrowingTaskGroup",
	"I": "Swift.AsyncIteratorProtocol",
	"i": "Swift.AsyncSequence",
	"J": "Swift.UnownedJob",
	"M": "Swift.MainActor",
	"P": "Swift.TaskPriority",
	"S": "Swift.AsyncStream",
	"s": "Swift.AsyncThrowingStream",
	"T": "Swift.Task",
	"t": "Swift.UnsafeCurrentTask",
}

// MangledType is a mangled type map
var MangledType = map[string]string{
	"Bb":        "Builtin.BridgeObject",
	"BB":        "Builtin.UnsafeValueBuffer",
	"Bc":        "Builtin.RawUnsafeContinuation",
	"BD":        "Builtin.DefaultActorStorage",
	"Be":        "Builtin.Executor",
	"Bd":        "Builtin.NonDefaultDistributedActorStorage",
	"Bf":        "Builtin.Float<n>",
	"Bi":        "Builtin.Int<n>",
	"BI":        "Builtin.IntLiteral",
	"Bj":        "Builtin.Job",
	"BP":        "Builtin.PackIndex",
	"BO":        "Builtin.UnknownObject",
	"Bo":        "Builtin.NativeObject",
	"Bp":        "Builtin.RawPointer",
	"Bt":        "Builtin.SILToken",
	"Bv":        "Builtin.Vec<n>x<type>",
	"Bw":        "Builtin.Word",
	"c":         "function type (escaping)",
	"X":         "special function type",
	"Sg":        "?", // shortcut for: type 'ySqG'
	"ySqG":      "?", // optional type
	"GSg":       "?",
	"_pSg":      "?",
	"SgSg":      "??",
	"ypG":       "Any",
	"p":         "Any",
	"SSG":       "String",
	"SSGSg":     "String?",
	"SSSgG":     "String?",
	"SpySvSgGG": "UnsafeMutablePointer<UNumberFormat?>",
	"SiGSg":     "Int?",
	"Xo":        "@unowned type",
	"Xu":        "@unowned(unsafe) type",
	"Xw":        "@weak type",
	"XF":        "function implementation type (currently unused)",
	"Xb":        "SIL @box type (deprecated)",
	"Xx":        "SIL box type",
	"XD":        "dynamic self type",
	"m":         "metatype without representation",
	"XM":        "metatype with representation",
	"Xp":        "existential metatype without representation",
	"Xm":        "existential metatype with representation",
	"Xe":        "(error)",
	"x":         "A", // generic param, depth=0, idx=0
	"q_":        "B", // dependent generic parameter
	"yxq_G":     "<A, B>",
	"xq_":       "<A, B>",
	"Sb":        "Swift.Bool",
	"Qz":        "==",
	"Qy_":       "==",
	"Qy0_":      "==",
	"SgXw":      "?",
}
