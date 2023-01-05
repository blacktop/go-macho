package types

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/blacktop/go-macho/pkg/codesign/types/plist"
)

// <?xml version="1.0" encoding="UTF-8"?>
// <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
// <plist version="1.0">
// <dict>
// 	<key>com.apple.private.security.container-required</key>
// 	<false/>
// 	<key>platform-application</key>
// 	<true/>
// </dict>
// </plist>

type item struct {
	Key string `asn1:"utf8"`
	Val any
}

type boolItem struct {
	Key string `asn1:"utf8"`
	Val bool
}

type stringItem struct {
	Key string `asn1:"utf8"`
	Val string `asn1:"utf8"`
}

type stringSliceItem struct {
	Key string `asn1:"utf8"`
	Val []string
}

func DerEncodeEntitlements(input string) ([]byte, error) {
	var entitlements map[string]any

	if err := plist.NewXMLDecoder(strings.NewReader(input)).Decode(&entitlements); err != nil {
		return nil, fmt.Errorf("failed to decode entitlements plist: %w", err)
	}

	var items []any
	for k, v := range entitlements {
		switch t := v.(type) {
		case bool:
			items = append(items, boolItem{k, t})
		case string:
			items = append(items, stringItem{k, t})
		case []any:
			var stringSlice []string
			for _, s := range t {
				stringSlice = append(stringSlice, s.(string))
			}
			items = append(items, stringSliceItem{k, stringSlice})
		default:
			items = append(items, item{k, v})
		}
	}

	return asn1.MarshalWithParams(items, "set")
}
