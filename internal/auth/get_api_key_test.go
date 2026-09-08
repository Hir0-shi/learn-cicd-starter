package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr string
	}{
		{
			name:    "missing authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:    "empty authorization header",
			headers: http.Header{"Authorization": {""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:    "malformed no space",
			headers: http.Header{"Authorization": {"ApiKey123"}},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		{
			name:    "malformed wrong prefix",
			headers: http.Header{"Authorization": {"Bearer abc123"}},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": {"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("GetAPIKey() unexpected nil error")
				}
				if err.Error() != tt.wantErr {
					t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", gotKey, tt.wantKey)
			}
		})
	}
}
