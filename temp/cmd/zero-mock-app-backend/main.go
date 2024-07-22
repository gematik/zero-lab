package main

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

var (
	upgrader = websocket.Upgrader{}
)

type ErrorType struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

type EchoRequestMessageType struct {
	Message string `json:"message"`
}

type EchoResponseMessageType struct {
	Message string          `json:"message"`
	Request HttpRequestType `json:"request"`
}

type HttpRequestType struct {
	// Method is the HTTP method
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Proto   string      `json:"proto"`
	Headers http.Header `json:"headers"`
}

type EchoResponseDTO struct {
	Request HttpRequestType `json:"http_request"`
}

func main() {
	// Create a new Echo instance
	e := echo.New()

	e.Any("/api/echo", func(c echo.Context) error {
		return c.JSON(http.StatusOK, EchoResponseDTO{
			Request: httpRequestToDTO(c.Request()),
		})
	})

	// Register a WebSocket handler
	e.GET("/ws/echo", func(c echo.Context) error {
		// Upgrade the HTTP connection to a WebSocket
		ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
		if err != nil {
			return err
		}
		defer ws.Close()

		// Read messages from the WebSocket
		for {
			messageType, msg, err := ws.ReadMessage()
			if err != nil {
				slog.Error("error reading message", "error", err)
				return err
			}
			if messageType != websocket.TextMessage {
				ws.WriteJSON(ErrorType{
					Code:        "invalid_message_type",
					Description: "Only text messages are supported",
				})
				continue
			}

			parsedMsg := new(EchoRequestMessageType)
			err = json.Unmarshal(msg, &parsedMsg)
			if err != nil {
				ws.WriteJSON(ErrorType{
					Code:        "invalid_message_format",
					Description: "Invalid JSON format",
				})
				continue
			}

			err = ws.WriteJSON(EchoResponseMessageType{
				Message: parsedMsg.Message,
				Request: httpRequestToDTO(c.Request()),
			})
			if err != nil {
				slog.Error("error writing message", "error", err)
				return err
			}

		}
	})

	// Start the Echo server
	e.Logger.Fatal(e.Start(":8091"))
}

func httpRequestToDTO(r *http.Request) HttpRequestType {
	return HttpRequestType{
		Method:  r.Method,
		URL:     r.URL.String(),
		Proto:   r.Proto,
		Headers: r.Header,
	}
}
