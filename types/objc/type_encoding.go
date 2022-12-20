package objc

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// ref - https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html

var typeEncoding = map[string]string{
	"":  "void",
	"@": "id",
	"#": "Class",
	":": "SEL",
	// "c": "char",
	"c": "BOOL", // or "char"
	"C": "unsigned char",
	"s": "short",
	"S": "unsigned short",
	"i": "int",
	"I": "unsigned int",
	"l": "long",
	"L": "unsigned long",
	"q": "int64",
	"Q": "unsigned int64",
	"t": "int128",
	"T": "unsigned int128",
	"f": "float",
	"d": "double",
	"D": "long double",
	"b": "bit field",
	"B": "BOOL",
	"v": "void",
	"z": "size_t",
	"Z": "int32",
	"w": "wchar_t",
	// "?": "unknown",
	"?": "void", // or "undefined"
	"^": "*",
	"*": "char *",
	"%": "NXAtom",
	// "[":  "", // _C_ARY_B
	// "]":  "", // _C_ARY_E
	// "(":  "", // _C_UNION_B
	// ")":  "", // _C_UNION_E
	// "{":  "", // _C_STRUCT_B
	// "}":  "", // _C_STRUCT_E
	"!":  "vector",
	"Vv": "void",
	"^?": "IMP", // void *
}
var typeSpecifiers = map[string]string{
	"A": "atomic",
	"j": "_Complex",
	"!": "vector",
	"r": "const",
	"n": "in",
	"N": "inout",
	"o": "out",
	"O": "by copy",
	"R": "by ref",
	"V": "one way",
	"+": "gnu register",
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
func decodeMethodTypes(encodedTypes string) (string, string) {
	var argTypes []string

	// skip return type
	encArgs := strings.TrimLeft(skipFirstType(encodedTypes), "0123456789")

	for _, arg := range getArguments(encArgs) {
		argTypes = append(argTypes, arg.DecType)
	}
	if len(argTypes) == 2 {
		return getReturnType(encodedTypes), ""
	} else if len(argTypes) > 2 {
		return getReturnType(encodedTypes), fmt.Sprintf("(%s)", strings.Join(argTypes[2:], ", "))
	}
	return getReturnType(encodedTypes), fmt.Sprintf("(%s)", strings.Join(argTypes, ", "))
}

func getPropertyAttributeTypes(attrs string) string {
	// var ivarStr string
	var typeStr string
	var attrsStr string
	var attrsList []string

	for _, attr := range strings.Split(attrs, ",") {
		if strings.HasPrefix(attr, propertyType) {
			attr = strings.TrimPrefix(attr, propertyType)
			if strings.HasPrefix(attr, "@\"") {
				typeStr = strings.Trim(attr, "@\"") + " *"
			} else {
				if val, ok := typeEncoding[attr]; ok {
					typeStr = val + " "
				}
			}
		} else if strings.HasPrefix(attr, propertyIVar) {
			// found ivar name
			// ivarStr = strings.TrimPrefix(attr, propertyIVar)
			continue
		} else {
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
				attrsList = append(attrsList, "dynamic")
			case propertyStrong:
				attrsList = append(attrsList, "collectable")
			}
		}
	}

	if len(attrsList) > 0 {
		attrsStr = fmt.Sprintf("(%s) ", strings.Join(attrsList, ", "))
	}

	return fmt.Sprintf("%s%s", attrsStr, typeStr)
}

func getIVarType(ivType string) string {
	if strings.HasPrefix(ivType, "@\"") && len(ivType) > 1 {
		return strings.Trim(ivType, "@\"") + " *"
	}
	return decodeType(ivType) + " "
}

func decodeType(encType string) string {
	var s string

	if typ, ok := typeEncoding[encType]; ok {
		return typ
	}

	if strings.HasPrefix(encType, "^") {
		return decodeType(encType[1:]) + " *"
	}

	if spec, ok := typeSpecifiers[encType[:1]]; ok {
		return spec + " " + decodeType(encType[1:])
	}

	if strings.HasPrefix(encType, "@\"") && len(encType) > 1 {
		return strings.Trim(encType, "@\"")
	}

	if len(encType) > 2 {
		if strings.ContainsRune(encType[:2], '[') { // ARRAY
			inner := decodeType(encType[strings.IndexByte(encType, '[')+1 : strings.LastIndexByte(encType, ']')])
			s += decodeArray(inner)
		} else if strings.ContainsRune(encType, '{') { // STRUCT
			inner := encType[strings.IndexByte(encType, '{')+1 : strings.LastIndexByte(encType, '}')]
			s += "struct "
			if strings.HasPrefix(inner, "@\"") && len(inner) > 1 {
				inner = strings.Trim(inner, "@\"")
			}
			if strings.ContainsRune(inner, '=') {
				idx := strings.Index(inner, "=")
				inner = inner[:idx]
			}
			s += inner
			// s += decodeStructure(inner)
		} else if strings.ContainsRune(encType, '(') { // UNION
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
	return fmt.Sprintf("[%s]%s", arrayType[:numIdx+1], decodeType(arrayType[numIdx+1:]))
}

func decodeStructure(structType string) string {
	sOut := "struct "
	sOut += decodeType(structType)
	if strings.ContainsRune(sOut, '=') {
		sOut = sOut[:strings.Index(sOut, "=")]
	}
	return sOut
}

// TODO - finish
func decodeUnion(unionType string) string {
	return unionType
}

func getReturnType(types string) string {

	args := skipFirstType(types)
	encodedRet := strings.TrimSuffix(types, args)

	return decodeType(encodedRet)
}

func skipFirstType(typedesc string) string {
	i := 0
	typesStr := []byte(typedesc)

	for {
		char := typesStr[i]
		i++
		switch char {
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
			break
		case '@': /* objects */
			if typesStr[0] == '?' {
				i++ /* Blocks */
			}
			return string(typesStr[i:])
		case '[': /* arrays */
			return string(typesStr[bytes.IndexByte(typesStr, ']')+1:])
			// return typedesc[subtypeUntil(typedesc, ']')+1:]
		case '{': /* structures */
			return string(typesStr[bytes.IndexByte(typesStr, '}')+1:])
			// return typedesc[subtypeUntil(typedesc, '}')+1:]
		case '(': /* unions */
			return string(typesStr[bytes.IndexByte(typesStr, ')')+1:])
			// return typedesc[subtypeUntil(typedesc, ')')+1:]
		default: /* basic types */
			return string(typesStr[i:])
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
		if strings.HasPrefix(types, "+") {
			types = strings.TrimSuffix(types, "+")
		}
		// Traverse (possibly negative) argument offset
		if strings.HasPrefix(types, "-") {
			types = strings.TrimSuffix(types, "-")
		}
		types = strings.TrimLeft(types, "0123456789")

		nargs++
	}

	return nargs
}

func getArguments(encArgs string) []methodEncodedArg {
	var args []methodEncodedArg

	for _, t := range regexp.MustCompile(`.\d+`).FindAllString(encArgs, -1) {
		args = append(args, methodEncodedArg{
			DecType:   decodeType(string(t[0])),
			EncType:   string(t[0]),
			StackSize: t[1:],
		})
	}
	return args
}

// func skipFirstType(typedesc string) string {
// 	for {
// 		switch typedesc[0] {
// 		case 'O': // bycopy
// 			fallthrough
// 		case 'n': // in
// 			fallthrough
// 		case 'o': // out
// 			fallthrough
// 		case 'N': // inout
// 			fallthrough
// 		case 'r': // const
// 			fallthrough
// 		case 'V': // oneway
// 			fallthrough
// 		case '^': // pointers
// 			typedesc = typedesc[1:]
// 		case '@': // objects
// 			if typedesc[1] == '?' {
// 				typedesc = typedesc[2:] // Blocks
// 			}
// 			return typedesc[1:]
// 			// arrays
// 		case '[':
// 			for typedesc[0] >= '0' && typedesc[0] <= '9' {
// 				typedesc = typedesc[1:]
// 			}
// 			return typedesc[subtypeUntil(typedesc, ']')+1:]
// 			// structures
// 		case '{':
// 			return typedesc[subtypeUntil(typedesc, '}')+1:]
// 			// unions
// 		case '(':
// 			return typedesc[subtypeUntil(typedesc, ')')+1:]
// 			// basic types
// 		default:
// 			return typedesc
// 		}
// 		typedesc = typedesc[1:]
// 	}
// }

func subtypeUntil(typedesc string, end byte) int {
	var level int = 0
	typedesc += "\x00" // Ensure null termination
	var head = typedesc

	for typedesc[0] != 0 {
		if typedesc[0] == 0 || (level == 0 && typedesc[0] == end) {
			return len(typedesc) - len(head)
		}

		switch typedesc[0] {
		case ']', '}', ')':
			level -= 1
		case '[', '{', '(':
			level += 1
		}

		typedesc = typedesc[1:]
	}

	return 0
}
