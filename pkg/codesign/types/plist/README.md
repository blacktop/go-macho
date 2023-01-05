# OS X XML Plist library for Go
![Go](https://github.com/groob/plist/workflows/Go/badge.svg)

The plist library is used for decoding and encoding XML Plists, usually from HTTP streams.

Example:
```
func someHTTPHandler(w http.ResponseWriter, r *http.Request) {
	var sparseBundleHeader struct {
		InfoDictionaryVersion *string `plist:"CFBundleInfoDictionaryVersion"`
		BandSize              *uint64 `plist:"band-size"`
		BackingStoreVersion   int     `plist:"bundle-backingstore-version"`
		DiskImageBundleType   string  `plist:"diskimage-bundle-type"`
		Size                  uint64  `plist:"unknownKey"`
	}

    // decode an HTTP request body into the sparseBundleHeader struct
	if err := plist.NewXMLDecoder(r.Body).Decode(&sparseBundleHeader); err != nil {
		log.Println(err)
        return
	}
}
```

# Credit
This library is based of [DHowett's](https://github.com/DHowett/go-plist) library but has an API that's more similar to the XML and JSON libraries in the standard library. The plist.Decoder() accepts an `io.Reader` instead of an `io.ReadSeeker` 
