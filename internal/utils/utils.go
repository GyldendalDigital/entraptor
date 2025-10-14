package utils

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

var APINoErrorHandlingMessage = APIErrorMessage("internal_server_error")

func APIErrorMessage(message string) map[string]string {
	return map[string]string{"error": message}
}

func APIUnhandledError(w http.ResponseWriter) {
	APIError(w, APINoErrorHandlingMessage, http.StatusInternalServerError)
}

func APIBadRequest(w http.ResponseWriter) {
	APIError(w, APIErrorMessage("invalid_parameters"), http.StatusBadRequest)
}

func APIWrongClaims(w http.ResponseWriter) {
	APIError(w, APIErrorMessage("insufficient_claims"), http.StatusUnauthorized)
}

func APINotFound(w http.ResponseWriter) {
	APIError(w, APIErrorMessage("not_found"), http.StatusNotFound)
}

func APIUnauthorized(w http.ResponseWriter) {
	APIError(w, APIErrorMessage("unauthorized"), http.StatusUnauthorized)
}

func APINotImplemented(w http.ResponseWriter) {
	APIError(w, APIErrorMessage("not_implemented"), http.StatusNotImplemented)
}

func APIErrorHandler(w http.ResponseWriter, message string, status int) {
	APIError(w, APIErrorMessage(message), status)
}

func APIError(w http.ResponseWriter, obj any, status int) {
	w.Header().Add("Content-Type", "application/json; charset=utf-8")
	result, err := json.Marshal(obj)
	if err != nil {
		slog.Error("Failed to generate json from code object", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{\"error\":\"internal_error\"}"))
		return
	}
	w.WriteHeader(status)
	w.Write(result)
}

func APIResponse(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	switch v := obj.(type) {
	case []byte:
		w.Write(v)
	case string:
		w.Write([]byte(v))
	default:
		result, err := json.Marshal(obj)
		if err != nil {
			slog.Error("Failed to generate json from code object", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("{\"error\":\"internal_error\"}"))
			return
		}
		w.Write(result)
	}
}

func APINoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent) // 204
}
