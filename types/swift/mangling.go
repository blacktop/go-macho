package swift

//go:generate go run ./cmd/genstandardtypes -def StandardTypesMangling.def -out standard_types_generated.go

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
