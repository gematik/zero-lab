package util

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
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

func ResponseToText(resp *http.Response) string {
	sb := strings.Builder{}
	sb.WriteString("HTTP/1.1 ")
	sb.WriteString(resp.Status)
	sb.WriteString("\n")
	for k, v := range resp.Header {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(v, ", "))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		sb.WriteString(err.Error())
	} else {
		resp.Body = io.NopCloser(bytes.NewBuffer(body))
		sb.WriteString(string(body))
	}
	return sb.String()
}
