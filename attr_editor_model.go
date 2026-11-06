package main

import (
	"fmt"
	"radsec-windows-tester/protocol"
	"strings"
)

type attributeRow struct{ Name, Expression string }

func makeAttributeRow(name, mode, value string) (attributeRow, error) {
	kind := ""
	for _, option := range protocol.SelectableAttributes() {
		if option.Name == name {
			kind = option.Kind
			break
		}
	}
	if kind == "" {
		return attributeRow{}, fmt.Errorf("attribute is not selectable")
	}
	value = strings.TrimSpace(value)
	if strings.ContainsAny(value, ";\r\n") {
		return attributeRow{}, fmt.Errorf("value cannot contain separators")
	}
	switch mode {
	case "Static":
		if value == "" {
			return attributeRow{}, fmt.Errorf("enter a value")
		}
	case "Random range":
		if kind != "integer" && kind != "integer64" && kind != "enum" && kind != "time" {
			return attributeRow{}, fmt.Errorf("random range requires numeric attribute")
		}
		value = "random(" + value + ")"
	case "Random length":
		if kind != "text" && kind != "string" {
			return attributeRow{}, fmt.Errorf("random length requires text attribute")
		}
		value = "random(" + value + ")"
	default:
		return attributeRow{}, fmt.Errorf("unknown value mode")
	}
	row := attributeRow{Name: name, Expression: value}
	if _, err := protocol.ParseAttributes(renderAttributeRows([]attributeRow{row})); err != nil {
		return attributeRow{}, err
	}
	return row, nil
}
func renderAttributeRows(rows []attributeRow) string {
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, row.Name+" = "+row.Expression)
	}
	return strings.Join(parts, "; ")
}
func parseAttributeRows(extra string) ([]attributeRow, error) {
	rows := []attributeRow{}
	for _, part := range strings.Split(strings.ReplaceAll(extra, "\n", ";"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pair := strings.SplitN(part, "=", 2)
		if len(pair) != 2 {
			return nil, fmt.Errorf("invalid Extra syntax")
		}
		name, value := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		mode, argument := "Static", value
		if strings.HasPrefix(value, "random(") && strings.HasSuffix(value, ")") {
			argument = value[len("random(") : len(value)-1]
			mode = "Random length"
			if strings.Contains(argument, ",") {
				mode = "Random range"
			}
		}
		row, err := makeAttributeRow(name, mode, argument)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
