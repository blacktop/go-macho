package objc

import (
	"fmt"
	"strings"
	"unicode"
)

// ref - https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html

var typeEncoding = map[string]string{
	"":   "",                      // Nothing
	"!":  "/* vector */",          // TODO: review
	"#":  "Class",                 // Objective-C Class
	"%":  "const char *",          // TODO: review
	"*":  "char *",                // C String
	":":  "SEL",                   // Objective-C Selector
	"?":  "void * /* unknown */",  // Unknown (likely a C Function and unlikely an Objective-C Block)
	"@":  "id",                    // Objective-C Pointer
	"@?": "id /* block */",        // Objective-C Block Pointer
	"B":  "_Bool",                 // C Boolean
	"C":  "unsigned char",         // Unsigned C Character
	"D":  "long double",           // Extended-Precision C Floating-Point
	"I":  "unsigned int",          // Unsigned C Integer
	"L":  "unsigned long",         // Unsigned C Long Integer
	"Q":  "unsigned long long",    // Unsigned C Long-Long Integer
	"S":  "unsigned short",        // Unsigned C Short Integer
	"T":  "unsigned __int128",     // Unsigned C 128-bit Integer
	"^":  "*",                     // C Pointer
	"^?": "void * /* function */", // C Function Pointer
	"b":  ":",                     // C Bit Field
	"c":  "char",                  // Signed C Character or Objective-C Boolean
	"d":  "double",                // Double-Precision C Floating-Point
	"f":  "float",                 // Single-Precision C Floating-Point
	"i":  "int",                   // Signed C Integer
	"l":  "long",                  // Signed C Long Integer
	"q":  "long long",             // Signed C Long-Long Integer
	"s":  "short",                 // Signed C Short Integer
	"t":  "__int128",              // Signed C 128-bit Integer
	"v":  "void",                  // C Void
	// "%": "NXAtom", // TODO: review
	// "Z": "int32", // TODO: review
	// "w": "wchar_t", // TODO: review
	// "z": "size_t", // TODO: review
	// "(": "", // C Union Begin
	// ")": "", // C Union End
	// "[": "", // C Array Begin
	// "]": "", // C Array End
	// "{": "", // C Struct Begin
	// "}": "", // C Struct End
}

var typeSpecifiers = map[string]string{
	"+": "/* gnu register */", // TODO: review
	"A": "_Atomic",
	"N": "inout",
	"O": "bycopy",
	"R": "byref",
	"V": "oneway",
	"j": "_Complex",
	"n": "in",
	"o": "out",
	"r": "const",
	"|": "/* gc invisible */", // TODO: review
}

const (
	propertyReadOnly  = "R" // property is read-only.
	propertyBycopy    = "C" // property is a copy of the value last assigned
	propertyByref     = "&" // property is a reference to the value last assigned
	propertyDynamic   = "D" // property is dynamic
	propertyGetter    = "G" // followed by getter selector name
	propertySetter    = "S" // followed by setter selector name
	propertyIVar      = "V" // followed by instance variable  name
	propertyType      = "T" // followed by old-style type encoding.
	propertyWeak      = "W" // 'weak' property
	propertyStrong    = "P" // property GC'able
	propertyAtomic    = "A" // property atomic
	propertyNonAtomic = "N" // property non-atomic
	propertyOptional  = "?" // property optional
)

type methodEncodedArg struct {
	DecType   string // decoded argument type
	EncType   string // encoded argument type
	StackSize string // variable stack size
}

type varEncodedType struct {
	Head     string // type specifiers
	Variable string // variable name
	DecType  string // decoded variable type
	EncType  string // encoded variable type
	Tail     string // type output tail
}

// decodeMethodTypes decodes the method types and returns a return type and the argument types
func decodeMethodTypes(encodedTypes string) (string, []string) {
	var argTypes []string

	// skip return type
	encArgs := strings.TrimLeft(skipFirstType(encodedTypes), "0123456789")

	for idx, arg := range getArguments(encArgs) {
		switch idx {
		case 0:
			argTypes = append(argTypes, fmt.Sprintf("(%s)self", arg.DecType))
		case 1:
			argTypes = append(argTypes, fmt.Sprintf("(%s)id", arg.DecType))
		default:
			argTypes = append(argTypes, fmt.Sprintf("(%s)", arg.DecType))
		}
	}
	return getReturnType(encodedTypes), argTypes
}

func getLastCapitalizedPart(s string) string {
	start := len(s)
	for i := len(s) - 1; i >= 0; i-- {
		if unicode.IsUpper(rune(s[i])) {
			start = i
		} else if start != len(s) {
			break
		}
	}
	if start == len(s) {
		return s
	}
	return strings.ToLower(s[start:])
}

func getMethodWithArgs(method, returnType string, args []string) string {
	if len(args) <= 2 {
		return fmt.Sprintf("(%s)%s;", returnType, method)
	}
	args = args[2:] // skip self and SEL

	parts := strings.Split(method, ":")

	var methodStr string
	if len(parts) > 1 { // method has arguments based on SEL having ':'
		for idx, part := range parts {
			argName := getLastCapitalizedPart(part)
			if len(part) == 0 || idx >= len(args) {
				break
			}
			methodStr += fmt.Sprintf("%s:%s ", part, args[idx]+argName)
		}
		return fmt.Sprintf("(%s)%s;", returnType, strings.TrimSpace(methodStr))
	}
	// method has no arguments based on SEL not having ':'
	return fmt.Sprintf("(%s)%s;", returnType, method)
}

func getPropertyType(attrs string) (typ string) {
	if strings.HasPrefix(attrs, propertyType) {
		var attr string
		var typParts []string
		parts := strings.Split(attrs, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			sub := parts[i]
			switch string(sub[0]) {
			case propertyReadOnly:
			case propertyBycopy:
			case propertyByref:
			case propertyDynamic:
			case propertyGetter:
			case propertySetter:
			case propertyIVar:
			case propertyWeak:
			case propertyStrong:
			case propertyAtomic:
			case propertyNonAtomic:
			case propertyOptional:
			case propertyType:
				typParts = append([]string{strings.TrimPrefix(sub, propertyType)}, typParts...)
				attr = strings.Join(typParts, ",")
			default:
				typParts = append([]string{sub}, typParts...)
			}
		}
		if strings.HasPrefix(attr, "@\"") {
			typ = strings.Trim(attr, "@\"")
			typ = strings.ReplaceAll(typ, "><", ", ")
			if strings.HasPrefix(typ, "<") {
				typ = "id " + typ + " "
			} else {
				typ += " *"
			}
		} else {
			typ = decodeType(attr) + " "
		}
	} else {
		typ = "?"
	}
	return typ
}

func getPropertyAttributeTypes(attrs string) (string, bool) {
	// var ivarStr string
	var attrsStr string
	var attrsList []string

	isOptional := false

	for _, attr := range strings.Split(attrs, ",") {
		if strings.HasPrefix(attr, propertyIVar) {
			// found ivar name
			// ivarStr = strings.TrimPrefix(attr, propertyIVar)
			continue
		}
		// TODO: handle the following cases
		// @property struct YorkshireTeaStruct structDefault; ==> T{YorkshireTeaStruct="pot"i"lady"c},VstructDefault
		// @property int (*functionPointerDefault)(char *);   ==> T^?,VfunctionPointerDefault
		switch attr {
		case propertyGetter:
			attr = strings.TrimPrefix(attr, propertyGetter)
			attrsList = append(attrsList, fmt.Sprintf("getter=%s", attr))
		case propertySetter:
			attr = strings.TrimPrefix(attr, propertySetter)
			attrsList = append(attrsList, fmt.Sprintf("setter=%s", attr))
		case propertyReadOnly:
			attrsList = append(attrsList, "readonly")
		case propertyNonAtomic:
			attrsList = append(attrsList, "nonatomic")
		case propertyAtomic:
			attrsList = append(attrsList, "atomic")
		case propertyBycopy:
			attrsList = append(attrsList, "copy")
		case propertyByref:
			attrsList = append(attrsList, "retain")
		case propertyWeak:
			attrsList = append(attrsList, "weak")
		case propertyDynamic:
			// omit the @dynamic directive because it must never appear inside
			// @interface and @protocol blocks, only in @implementation blocks
		case propertyStrong:
			attrsList = append(attrsList, "collectable")
		case propertyOptional:
			isOptional = true
		}
	}

	if len(attrsList) > 0 {
		attrsStr = fmt.Sprintf("(%s) ", strings.Join(attrsList, ", "))
	}

	return attrsStr, isOptional
}

func getIVarType(ivType string) string {
	if strings.HasPrefix(ivType, "@\"") && len(ivType) > 1 {
		ivType = strings.Trim(ivType, "@\"")
		ivType = strings.ReplaceAll(ivType, "><", ", ")
		if strings.HasPrefix(ivType, "<") {
			return "id " + ivType + " "
		}
		return ivType + " *"
	}
	return decodeType(ivType) + " "
}

func getReturnType(types string) string {
	if len(types) == 0 {
		return ""
	}
	return decodeType(strings.TrimSuffix(types, skipFirstType(types)))
}

func decodeType(encType string) string {
	var s string

	if typ, ok := typeEncoding[encType]; ok {
		return typ
	}

	if strings.HasPrefix(encType, "^") {
		if typ, ok := typeEncoding[encType]; ok {
			return typ
		}
		return decodeType(encType[1:]) + " *" // pointer
	}

	if spec, ok := typeSpecifiers[string(encType[0])]; ok { // TODO: can there be more than 2 specifiers?
		if len(encType) > 1 {
			if spec2, ok := typeSpecifiers[string(encType[1])]; ok {
				return spec2 + " " + spec + " " + decodeType(encType[2:])
			}
		}
		return spec + " " + decodeType(encType[1:])
	}

	if strings.HasPrefix(encType, "@\"") && len(encType) > 1 {
		return strings.Trim(encType, "@\"") + " *"
	}

	if strings.HasPrefix(encType, "b") {
		return decodeBitfield(encType)
	}

	if len(encType) > 2 {
		if strings.HasPrefix(encType, "[") { // ARRAY
			inner := encType[strings.IndexByte(encType, '[')+1 : strings.LastIndexByte(encType, ']')]
			s += decodeArray(inner)
		} else if strings.HasPrefix(encType, "{") { // STRUCT
			if !(strings.Contains(encType, "{") && strings.Contains(encType, "}")) {
				return "?"
			}
			inner := encType[strings.IndexByte(encType, '{')+1 : strings.LastIndexByte(encType, '}')]
			s += decodeStructure(inner)
		} else if strings.HasPrefix(encType, "(") { // UNION
			inner := encType[strings.IndexByte(encType, '(')+1 : strings.LastIndexByte(encType, ')')]
			s += decodeUnion(inner)
		}
	}

	if len(s) == 0 {
		return encType
	}

	return s
}

func decodeArray(arrayType string) string {
	numIdx := strings.LastIndexAny(arrayType, "0123456789")
	if len(arrayType) == 1 {
		return fmt.Sprintf("x[%s]", arrayType)
	}
	return fmt.Sprintf("%s x[%s]", decodeType(arrayType[numIdx+1:]), arrayType[:numIdx+1])
}

func decodeStructure(structure string) string {
	return decodeStructOrUnion(structure, "struct")
}

func decodeUnion(unionType string) string {
	return decodeStructOrUnion(unionType, "union")
}

func decodeBitfield(bitfield string) string {
	span := encodingGetSizeOfArguments(bitfield)
	return fmt.Sprintf("unsigned int x:%d", span)
}

func getFieldName(field string) (string, string) {
	if strings.HasPrefix(field, "\"") {
		name, rest, ok := strings.Cut(strings.TrimPrefix(field, "\""), "\"")
		if !ok {
			return "", field
		}
		return name, rest
	}
	return "", field
}

func decodeStructOrUnion(typ, kind string) string {
	name, rest, _ := strings.Cut(typ, "=")
	if name == "?" {
		name = ""
	} else {
		name += " "
	}

	if len(rest) == 0 {
		return fmt.Sprintf("%s %s", kind, strings.TrimSpace(name))
	}

	var idx int
	var fields []string
	fieldName, rest := getFieldName(rest)
	field, rest, ok := CutType(rest)

	for ok {
		if fieldName != "" {
			dtype := decodeType(field)
			if strings.HasSuffix(dtype, " *") {
				fields = append(fields, fmt.Sprintf("%s%s;", dtype, fieldName))
			} else {
				fields = append(fields, fmt.Sprintf("%s %s;", dtype, fieldName))
			}
		} else {
			if strings.HasPrefix(field, "b") {
				span := encodingGetSizeOfArguments(field)
				fields = append(fields, fmt.Sprintf("unsigned int x%d:%d;", idx, span))
			} else if strings.HasPrefix(field, "[") {
				array := decodeType(field)
				array = strings.TrimSpace(strings.Replace(array, "x", fmt.Sprintf("x%d", idx), 1))
				fields = append(fields, array)
			} else {
				fields = append(fields, fmt.Sprintf("%s x%d;", decodeType(field), idx))
			}
			idx++
		}
		fieldName, rest = getFieldName(rest)
		field, rest, ok = CutType(rest)
	}

	return fmt.Sprintf("%s %s{ %s }", kind, name, strings.Join(fields, " "))
}

func skipFirstType(typStr string) string {
	i := 0
	typ := []byte(typStr)
	for {
		switch typ[i] {
		case 'O': /* bycopy */
			fallthrough
		case 'n': /* in */
			fallthrough
		case 'o': /* out */
			fallthrough
		case 'N': /* inout */
			fallthrough
		case 'r': /* const */
			fallthrough
		case 'V': /* oneway */
			fallthrough
		case '^': /* pointers */
			i++
		case '@': /* objects */
			if i+1 < len(typ) && typ[i+1] == '?' {
				i++ /* Blocks */
			} else if i+1 < len(typ) && typ[i+1] == '"' {
				i++
				for typ[i+1] != '"' {
					i++ /* Class */
				}
				i++
			}
			return string(typ[i+1:])
		case '[': /* arrays */
			i++
			for typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			return string(typ[i+subtypeUntil(string(typ[i:]), ']')+1:])
		case '{': /* structures */
			i++
			return string(typ[i+subtypeUntil(string(typ[i:]), '}')+1:])
		case '(': /* unions */
			i++
			return string(typ[i+subtypeUntil(string(typ[i:]), ')')+1:])
		default: /* basic types */
			i++
			return string(typ[i:])
		}
	}
}

func subtypeUntil(typ string, end byte) int {
	var level int
	head := typ
	for len(typ) > 0 {
		if level == 0 && typ[0] == end {
			return len(head) - len(typ)
		}
		switch typ[0] {
		case ']', '}', ')':
			level -= 1
		case '[', '{', '(':
			level += 1
		}
		typ = typ[1:]
	}
	return 0
}

func CutType(typStr string) (string, string, bool) {
	var i int

	if len(typStr) == 0 {
		return "", "", false
	}
	if len(typStr) == 1 {
		return typStr, "", true
	}

	typ := []byte(typStr)
	for {
		switch typ[i] {
		case 'O': /* bycopy */
			fallthrough
		case 'n': /* in */
			fallthrough
		case 'o': /* out */
			fallthrough
		case 'N': /* inout */
			fallthrough
		case 'r': /* const */
			fallthrough
		case 'V': /* oneway */
			fallthrough
		case '^': /* pointers */
			i++
		case '@': /* objects */
			if i+1 < len(typ) && typ[i+1] == '?' {
				i++ /* Blocks */
			} else if i+1 < len(typ) && typ[i+1] == '"' {
				i++
				for typ[i+1] != '"' {
					i++ /* Class */
				}
				i++
			}
			return string(typ[:i+1]), string(typ[i+1:]), true
		case 'b': /* bitfields */
			i++
			for i < len(typ) && typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			return string(typ[:i]), string(typ[i:]), true
		case '[': /* arrays */
			i++
			for typ[i] >= '0' && typ[i] <= '9' {
				i++
			}
			return string(typ[:i+subtypeUntil(string(typ[i:]), ']')+1]), string(typ[i+subtypeUntil(string(typ[i:]), ']')+1:]), true
		case '{': /* structures */
			i++
			return string(typ[:i+subtypeUntil(string(typ[i:]), '}')+1]), string(typ[i+subtypeUntil(string(typ[i:]), '}')+1:]), true
		case '(': /* unions */
			i++
			return string(typ[:i+subtypeUntil(string(typ[i:]), ')')+1]), string(typ[i+subtypeUntil(string(typ[i:]), ')')+1:]), true
		default: /* basic types */
			i++
			return string(typ[:i]), string(typ[i:]), true
		}
	}
}

func getNumberOfArguments(types string) int {
	var nargs int
	// First, skip the return type
	types = skipFirstType(types)
	// Next, skip stack size
	types = strings.TrimLeft(types, "0123456789")
	// Now, we have the arguments - count how many
	for len(types) > 0 {
		// Traverse argument type
		types = skipFirstType(types)
		// Skip GNU runtime's register parameter hint
		types = strings.TrimPrefix(types, "+")
		// Traverse (possibly negative) argument offset
		types = strings.TrimPrefix(types, "-")
		types = strings.TrimLeft(types, "0123456789")
		// Made it past an argument
		nargs++
	}
	return nargs
}

func getArguments(encArgs string) []methodEncodedArg {
	var args []methodEncodedArg
	t, rest, ok := CutType(encArgs)
	for ok {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		args = append(args, methodEncodedArg{
			EncType:   t,
			DecType:   decodeType(t),
			StackSize: rest[:i],
		})
		t, rest, ok = CutType(rest[i:])
	}
	return args
}

func encodingGetSizeOfArguments(typedesc string) uint {
	var stackSize uint

	stackSize = 0
	typedesc = skipFirstType(typedesc)

	for i := 0; i < len(typedesc); i++ {
		if typedesc[i] >= '0' && typedesc[i] <= '9' {
			stackSize = stackSize*10 + uint(typedesc[i]-'0')
		} else {
			break
		}
	}

	return stackSize
}
