package util

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func JWSToText(jwsData string) string {
	sb := strings.Builder{}
	parts := strings.Split(jwsData, ".")

	sb.WriteString("base64url(")
	sb.WriteString(tokenPartToText(parts[0]))
	sb.WriteString(").base64url(")
	sb.WriteString(tokenPartToText(parts[1]))
	sb.WriteString(").signature(")
	sb.WriteString(parts[2][0:10])
	sb.WriteString("...)\n")
	return sb.String()
}

func tokenPartToText(s string) string {
	dataBytes, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err.Error()
	}
	dataMap := make(map[string]interface{})
	err = json.Unmarshal(dataBytes, &dataMap)
	if err != nil {
		return string(dataBytes)
	}

	jsonBytes, err := json.MarshalIndent(dataMap, "  ", "  ")
	if err != nil {
		return err.Error()
	}
	return string(jsonBytes)
}
