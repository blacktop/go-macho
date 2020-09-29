package objc

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var typeEncoding = map[string]string{
	"@": "id",
	"#": "Class",
	":": "SEL",
	"c": "char",
	"C": "unsigned char",
	"s": "short",
	"S": "unsigned short",
	"i": "int",
	"I": "unsigned int",
	"l": "long",
	"L": "unsigned long",
	"q": "int64",
	"Q": "unsigned int64",
	"f": "float",
	"d": "double",
	"b": "bit field",
	"B": "bool",
	"v": "void",
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

type MethodTypes string

func (t MethodTypes) Decode() string {
	var proto string

	a := regexp.MustCompile(`\d+`)
	listTypes := a.Split(string(t), -1)
	fmt.Println(listTypes)
	// if list_types[0][0] in '{[(':
	//     proto = list_types[0]
	// else:
	//     proto = encoded_types.get(list_types[0], 'unknown ' + list_types[0])

	// proto += ' ' + name + '('
	// for t in list_types[3:]:
	//     if not t:
	//         continue
	//     if len(t) > 1 and t[0] in '{[(':
	//         proto += t + ', '
	//     else:
	//         proto += encoded_types.get(t, 'unknown ' + t) + ', '
	// proto = proto.rstrip(' ,') + ')'
	return proto
}

func getNumberOfArguments(types string) int {
	var count int

	types = skipFirstType(types)

	a := regexp.MustCompile(`\d+`)
	for _, t := range a.Split(types, -1) {
		if len(t) > 0 && t != "+" && t != "-" {
			count++
		}
	}

	return count
}

func getReturnType(types string) string {

	args := skipFirstType(types)
	encodedRet := strings.TrimSuffix(types, args)
	if val, ok := typeEncoding[encodedRet]; ok {
		return val
	}
	var retType string
	if strings.ContainsRune(encodedRet[:2], '[') {
		retType = encodedRet[strings.IndexByte(encodedRet, '[')+1 : strings.LastIndexByte(encodedRet, ']')]
	} else if strings.ContainsRune(encodedRet, '{') {
		retType = encodedRet[strings.IndexByte(encodedRet, '{')+1 : strings.LastIndexByte(encodedRet, '}')]
	} else if strings.ContainsRune(encodedRet, '(') {
		retType = encodedRet[strings.IndexByte(encodedRet, '(')+1 : strings.LastIndexByte(encodedRet, ')')]
	}

	if len(retType) == 0 {
		return encodedRet
	}

	if strings.ContainsRune(retType, '=') {
		retType = retType[:strings.Index(retType, "=")]
	}

	if strings.HasPrefix(encodedRet, "^") {
		return retType + " *"
	}

	if strings.HasPrefix(encodedRet, "r^") {
		return "const " + retType + " *"
	}

	return retType
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

			/* arrays */
		case '[':
			for (typesStr[i] >= '0') && (typesStr[i] <= '9') {
				i++
			}
			return string(typesStr[bytes.IndexByte(typesStr, ']')+1:])

			/* structures */
		case '{':
			end := bytes.IndexByte(typesStr, '}') + 1
			return string(typesStr[end:])

			/* unions */
		case '(':
			return string(typesStr[bytes.IndexByte(typesStr, ')')+1:])

			/* basic types */
		default:
			return string(typesStr[i:])
		}
	}
}
