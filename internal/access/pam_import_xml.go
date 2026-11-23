package access

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Devolutions Remote Desktop Manager writes two export shapes: the JSON one the
// importer started with and an XML one (<RDMExport><Connections><Connection>…)
// that File → Export produces by default and that carries the same objects.
// parseRDMXML turns the XML into the generic map form mapRDMConnection already
// reads, so one mapping serves both.
//
// What it does with the document:
//   - an element with child elements becomes a nested object (Terminal, RDP,
//     MetaInformation…), a leaf becomes its text, a repeated tag becomes a list;
//   - the embedded icon (<Image>, a base64 picture on every entry that has one)
//     is dropped: it is decoration, it is most of the file's size and it would be
//     stored on every imported entry;
//   - nothing is fetched or expanded: encoding/xml does not resolve external
//     entities, and the document is read as a stream with a depth limit.

// rdmXMLMaxDepth bounds nesting so a hostile document cannot exhaust the stack.
const rdmXMLMaxDepth = 32

// rdmXMLSkip are element names whose content is never kept.
var rdmXMLSkip = map[string]bool{"Image": true}

// looksLikeXML reports whether the payload is an XML document (a BOM and
// whitespace in front are ignored).
func looksLikeXML(data []byte) bool {
	d := bytes.TrimLeft(data, "\xef\xbb\xbf \t\r\n")
	return len(d) > 0 && d[0] == '<'
}

// parseRDMXML returns the connection objects of an RDM XML export.
func parseRDMXML(data []byte) ([]map[string]interface{}, error) {
	data = bytes.TrimLeft(data, "\xef\xbb\xbf")
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true

	var conns []map[string]interface{}
	var sawRoot bool
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("RDM export is not valid XML: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Connection":
			// A <Connection> found anywhere is one object, whether the export
			// wraps it in <Connections> or a bare one is pasted.
			obj, err := readRDMXMLObject(dec, 1)
			if err != nil {
				return nil, err
			}
			conns = append(conns, obj)
			sawRoot = true
		case "RDMExport", "Connections":
			sawRoot = true
		default:
			if !sawRoot {
				return nil, fmt.Errorf("unrecognized RDM export: root element <%s>", start.Name.Local)
			}
			// Anything else at this level (DatabaseID, Version…) is skipped whole.
			if err := dec.Skip(); err != nil {
				return nil, fmt.Errorf("RDM export is not valid XML: %w", err)
			}
		}
	}
	if !sawRoot {
		return nil, errors.New("unrecognized RDM export format (expected an RDMExport XML document)")
	}
	return conns, nil
}

// readRDMXMLObject reads the children of the element whose start tag was just
// consumed, up to and including its end tag.
func readRDMXMLObject(dec *xml.Decoder, depth int) (map[string]interface{}, error) {
	if depth > rdmXMLMaxDepth {
		return nil, errors.New("RDM export is nested too deeply")
	}
	obj := map[string]interface{}{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("RDM export is not valid XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if rdmXMLSkip[name] {
				if err := dec.Skip(); err != nil {
					return nil, fmt.Errorf("RDM export is not valid XML: %w", err)
				}
				continue
			}
			val, err := readRDMXMLValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			if prev, exists := obj[name]; exists {
				if list, ok := prev.([]interface{}); ok {
					obj[name] = append(list, val)
				} else {
					obj[name] = []interface{}{prev, val}
				}
			} else {
				obj[name] = val
			}
		case xml.EndElement:
			return obj, nil
		}
	}
}

// readRDMXMLValue reads one element's content: its text if it has no child
// elements, otherwise an object of them.
func readRDMXMLValue(dec *xml.Decoder, depth int) (interface{}, error) {
	if depth > rdmXMLMaxDepth {
		return nil, errors.New("RDM export is nested too deeply")
	}
	var text strings.Builder
	var obj map[string]interface{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("RDM export is not valid XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			text.Write(t)
		case xml.StartElement:
			if obj == nil {
				obj = map[string]interface{}{}
			}
			name := t.Name.Local
			if rdmXMLSkip[name] {
				if err := dec.Skip(); err != nil {
					return nil, fmt.Errorf("RDM export is not valid XML: %w", err)
				}
				continue
			}
			val, err := readRDMXMLValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			if prev, exists := obj[name]; exists {
				if list, ok := prev.([]interface{}); ok {
					obj[name] = append(list, val)
				} else {
					obj[name] = []interface{}{prev, val}
				}
			} else {
				obj[name] = val
			}
		case xml.EndElement:
			if obj != nil {
				return obj, nil
			}
			return strings.TrimSpace(text.String()), nil
		}
	}
}
