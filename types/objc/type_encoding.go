package objc

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var typeEncoding = map[string]string{
	"":  "void",
	"@": "id",
	"#": "Class",
	":": "SEL",
	// "c": "char",
	"c": "BOOL",
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
	"?": "unknown",
	"^": "*",
	"*": "char *",
	"%": "atom",
	// "[":  "",
	// "]":  "",
	// "(":  "",
	// ")":  "",
	// "{":  "",
	// "}":  "",
	"!":  "vector",
	"r":  "const",
	"n":  "in",
	"N":  "inout",
	"o":  "out",
	"O":  "by copy",
	"R":  "by ref",
	"V":  "one way",
	"Vv": "void",
	"^?": "IMP", // void *
	"r*": "const char *",
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

// decodeMethodTypes decodes the method types and returns a return type and the argument types
func decodeMethodTypes(encodedTypes string) (string, string) {
	var argTypes []string

	// skip return type
	encArgs := strings.TrimLeft(skipFirstType(encodedTypes), "0123456789")

	for _, arg := range getArguments(encArgs) {
		argTypes = append(argTypes, arg.DecType)
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
			if strings.HasPrefix(attr, "@") {
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
	if strings.HasPrefix(ivType, "@") {
		return strings.Trim(ivType, "@\"") + " *"
	}
	return getType(ivType)
}

func getType(encType string) string {
	if val, ok := typeEncoding[encType]; ok {
		return val
	}

	var decType string
	if len(encType) > 2 {
		if strings.ContainsRune(encType[:2], '[') {
			decType = encType[strings.IndexByte(encType, '[')+1 : strings.LastIndexByte(encType, ']')]
		} else if strings.ContainsRune(encType, '{') {
			decType = encType[strings.IndexByte(encType, '{')+1 : strings.LastIndexByte(encType, '}')]
		} else if strings.ContainsRune(encType, '(') {
			decType = encType[strings.IndexByte(encType, '(')+1 : strings.LastIndexByte(encType, ')')]
		}
	}

	if len(decType) == 0 {
		return encType
	}

	if strings.ContainsRune(decType, '=') {
		decType = decType[:strings.Index(decType, "=")]
	}

	if strings.HasPrefix(encType, "^") {
		return decType + " *"
	}

	if strings.HasPrefix(encType, "r^") {
		return "const " + decType + " *"
	}

	return decType
}

func getReturnType(types string) string {

	args := skipFirstType(types)
	encodedRet := strings.TrimSuffix(types, args)

	return getType(encodedRet)
}

func skipFirstType(types string) string {
	i := 0
	typesStr := []byte(types)

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
		case '{': /* structures */
			return string(typesStr[bytes.IndexByte(typesStr, '}')+1:])
		case '(': /* unions */
			return string(typesStr[bytes.IndexByte(typesStr, ')')+1:])
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

	// a := regexp.MustCompile(`\d+`)
	// for _, t := range a.Split(types, -1) {
	// 	if len(t) > 0 && t != "+" && t != "-" {
	// 		nargs++
	// 	}
	// }

	return nargs
}

func getArguments(encArgs string) []methodEncodedArg {
	var args []methodEncodedArg

	for _, t := range regexp.MustCompile(`.\d+`).FindAllString(encArgs, -1) {
		args = append(args, methodEncodedArg{
			DecType:   getType(string(t[0])),
			EncType:   string(t[0]),
			StackSize: t[1:],
		})
	}
	return args
}
