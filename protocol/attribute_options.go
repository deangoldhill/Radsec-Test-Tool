package protocol

import "sort"

type AttributeOption struct {
	Name, Kind string
	Supported  bool
	Reason     string
}

// StandardAttributes lists every assigned IANA base attribute, including
// protected or complex formats that this client intentionally cannot encode.
func StandardAttributes() []AttributeOption {
	out := make([]AttributeOption, 0, len(ianaAttributes))
	for name, spec := range ianaAttributes {
		option := AttributeOption{Name: name, Kind: spec.kind, Supported: true}
		if _, managed := managedAttributes[spec.typ]; managed {
			option.Supported, option.Reason = false, "Managed by the client; cannot be duplicated"
		} else {
			switch spec.kind {
			case "text", "string", "integer", "integer64", "enum", "time", "ipv4addr", "ipv6addr":
			default:
				option.Supported, option.Reason = false, "Complex or special format not encoded by this client"
			}
		}
		out = append(out, option)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SelectableAttributes exposes only base attributes the Extra parser can encode.
func SelectableAttributes() []AttributeOption {
	out := make([]AttributeOption, 0, len(ianaAttributes))
	for name, spec := range ianaAttributes {
		if _, managed := managedAttributes[spec.typ]; managed {
			continue
		}
		switch spec.kind {
		case "text", "string", "integer", "integer64", "enum", "time", "ipv4addr", "ipv6addr":
			out = append(out, AttributeOption{Name: name, Kind: spec.kind})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
