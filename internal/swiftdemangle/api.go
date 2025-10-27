package swiftdemangle

import (
	"bytes"
	"regexp"
)

var mangledTokenPattern = regexp.MustCompile(`(?:_?\$[sS]|S[oO])[A-Za-z0-9_]+`)

type Option func(*options)

type options struct {
	resolver SymbolicReferenceResolver
}

func WithResolver(r SymbolicReferenceResolver) Option {
	return func(o *options) {
		o.resolver = r
	}
}

func Demangle(mangled string, opts ...Option) (string, *Node, error) {
	cfg := buildOptions(opts...)
	dem := New(cfg.resolver)
	text, node, err := dem.DemangleString([]byte(mangled))
	if err != nil {
		return "", nil, err
	}
	return text, node, nil
}

func DemangleSymbolString(mangled string, opts ...Option) (string, *Node, error) {
	cfg := buildOptions(opts...)
	dem := New(cfg.resolver)
	node, err := dem.DemangleSymbol([]byte(mangled))
	if err != nil {
		return "", nil, err
	}
	return Format(node), node, nil
}

func DemangleTypeString(mangled string, opts ...Option) (string, *Node, error) {
	cfg := buildOptions(opts...)
	dem := New(cfg.resolver)
	clean := bytes.TrimPrefix([]byte(mangled), []byte("_"))
	node, err := dem.DemangleType(clean)
	if err != nil {
		return "", nil, err
	}
	return Format(node), node, nil
}

func DemangleBlob(blob string, opts ...Option) string {
	return mangledTokenPattern.ReplaceAllStringFunc(blob, func(token string) string {
		out, _, err := Demangle(token, opts...)
		if err != nil {
			return token
		}
		return out
	})
}

func buildOptions(opts ...Option) options {
	cfg := options{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}
