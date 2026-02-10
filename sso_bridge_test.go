package traefik_plugin_sso_bridge

import (
	"context"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCreateConfig tests the default configuration
func TestCreateConfig(t *testing.T) {
	config := CreateConfig()

	if config.CookieName != "SSO_AUTH_TICKET" {
		t.Errorf("Expected CookieName='SSO_AUTH_TICKET', got '%s'", config.CookieName)
	}

	if config.CstTokenName != "cst" {
		t.Errorf("Expected CstTokenName='cst', got '%s'", config.CstTokenName)
	}

	if config.CookieSecure {
		t.Error("Expected CookieSecure=false by default")
	}
}

// TestNew_ValidConfig tests plugin creation with valid config
func TestNew_ValidConfig(t *testing.T) {
	config := &Config{
		SecretKey: "TestKey8",
		ServiceID: "test_service",
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, config, "test-plugin")
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}

	if handler == nil {
		t.Fatal("Handler should not be nil")
	}

	// Verify default CstTokenName is set
	plugin := handler.(*SSOBridge)
	if plugin.config.CstTokenName != "cst" {
		t.Errorf("Expected default CstTokenName='cst', got '%s'", plugin.config.CstTokenName)
	}
}

// TestNew_MissingSecretKey tests plugin creation fails without secretKey
func TestNew_MissingSecretKey(t *testing.T) {
	config := &Config{
		ServiceID: "test",
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := New(ctx, next, config, "test")
	if err == nil {
		t.Error("Expected error for missing secretKey")
	}

	if err.Error() != "secretKey is required" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestNew_InvalidSecretKeyLength tests plugin creation fails with wrong key length
func TestNew_InvalidSecretKeyLength(t *testing.T) {
	tests := []struct {
		secretKey string
		name      string
	}{
		{"short", "too short"},
		{"toolong123", "too long"},
		{"", "empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				SecretKey: tt.secretKey,
				ServiceID: "test",
			}

			ctx := context.Background()
			next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

			_, err := New(ctx, next, config, "test")
			if err == nil {
				t.Errorf("Expected error for secretKey '%s'", tt.secretKey)
			}
		})
	}
}

// TestNew_MissingServiceID tests plugin creation fails without serviceId
func TestNew_MissingServiceID(t *testing.T) {
	config := &Config{
		SecretKey: "TestKey8",
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := New(ctx, next, config, "test")
	if err == nil {
		t.Error("Expected error for missing serviceId")
	}

	if err.Error() != "serviceId is required" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestEncryptDecrypt tests encryption and decryption roundtrip
func TestEncryptDecrypt(t *testing.T) {
	config := &Config{
		SecretKey: "TestKey8",
	}

	plugin := &SSOBridge{config: config}

	original := map[string]string{
		"ID":       "12345",
		"UserName": "testuser",
	}

	// Encrypt
	encrypted, err := plugin.encryptToken(original)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := plugin.decryptToken(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	if decrypted["UserName"] != original["UserName"] {
		t.Errorf("UserName mismatch: got '%s', want '%s'", decrypted["UserName"], original["UserName"])
	}

	if decrypted["ID"] != original["ID"] {
		t.Errorf("ID mismatch: got '%s', want '%s'", decrypted["ID"], original["ID"])
	}
}

// TestDecryptToken_ValidToken tests decryption with manually created token
func TestDecryptToken_ValidToken(t *testing.T) {
	config := &Config{
		SecretKey: "TestKey8",
	}

	plugin := &SSOBridge{config: config}

	// Create test token manually
	plainText := "ID=test123;UserName=john.doe;ServiceTicket=ST-12345"
	key := []byte("TestKey8")

	block, _ := des.NewCipher(key)
	plainBytes := plugin.addPadding([]byte(plainText), block.BlockSize())
	encrypted := make([]byte, len(plainBytes))
	mode := cipher.NewCBCEncrypter(block, key)
	mode.CryptBlocks(encrypted, plainBytes)
	token := base64.StdEncoding.EncodeToString(encrypted)

	// Decrypt
	userData, err := plugin.decryptToken(token)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if userData["UserName"] != "john.doe" {
		t.Errorf("Expected UserName='john.doe', got '%s'", userData["UserName"])
	}

	if userData["ID"] != "test123" {
		t.Errorf("Expected ID='test123', got '%s'", userData["ID"])
	}

	if userData["ServiceTicket"] != "ST-12345" {
		t.Errorf("Expected ServiceTicket='ST-12345', got '%s'", userData["ServiceTicket"])
	}
}

// TestServeHTTP_NoCookie_NoToken tests redirect when no auth provided
func TestServeHTTP_NoCookie_NoToken(t *testing.T) {
	config := CreateConfig()
	config.SecretKey = "TestKey8"
	config.ServiceID = "test"
	config.SSOLoginURL = "http://sso.example.com/login"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, config, "test-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://app.localhost/test", nil)

	handler.ServeHTTP(recorder, req)

	// Should redirect to SSO login
	if recorder.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", recorder.Code)
	}

	location := recorder.Header().Get("Location")
	if location == "" {
		t.Error("Expected Location header to be set")
	}

	if !contains(location, "sso.example.com") {
		t.Errorf("Expected redirect to SSO, got: %s", location)
	}
}

// TestServeHTTP_ValidCookie tests successful authentication via cookie
func TestServeHTTP_ValidCookie(t *testing.T) {
	config := CreateConfig()
	config.SecretKey = "TestKey8"
	config.ServiceID = "test"

	ctx := context.Background()

	authHeaderSet := false
	var receivedUsername string
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Check request headers (not response headers)
		receivedUsername = req.Header.Get("X-Auth-User")
		if receivedUsername != "" {
			authHeaderSet = true
		}
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, config, "test-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create valid token
	plugin := handler.(*SSOBridge)
	token, _ := plugin.encryptToken(map[string]string{
		"ID":       "123",
		"UserName": "testuser",
	})

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "SSO_AUTH_TICKET",
		Value: token,
	})

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", recorder.Code)
	}

	if !authHeaderSet {
		t.Error("Expected X-Auth-User header to be set in request")
	}

	if receivedUsername != "testuser" {
		t.Errorf("Expected X-Auth-User='testuser', got '%s'", receivedUsername)
	}
}

// TestServeHTTP_InvalidCookie tests authentication fails with invalid cookie
func TestServeHTTP_InvalidCookie(t *testing.T) {
	config := CreateConfig()
	config.SecretKey = "TestKey8"
	config.ServiceID = "test"
	config.SSOLoginURL = "http://sso.example.com/login"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(ctx, next, config, "test-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "SSO_AUTH_TICKET",
		Value: "invalid_token",
	})

	handler.ServeHTTP(recorder, req)

	// Should redirect to SSO login
	if recorder.Code != http.StatusFound {
		t.Errorf("Expected status 302, got %d", recorder.Code)
	}
}

// TestSetAuthHeaders tests that all auth headers are set correctly
func TestSetAuthHeaders(t *testing.T) {
	plugin := &SSOBridge{config: &Config{}}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)

	userData := map[string]string{
		"UserName": "john.doe",
		"ID":       "12345",
	}

	plugin.setAuthHeaders(req, userData)

	// Verify headers are set on request
	if got := req.Header.Get("X-Auth-User"); got != "john.doe" {
		t.Errorf("X-Auth-User: expected 'john.doe', got '%s'", got)
	}

	if got := req.Header.Get("X-Auth-ID"); got != "12345" {
		t.Errorf("X-Auth-ID: expected '12345', got '%s'", got)
	}

	if got := req.Header.Get("X-Auth-Source"); got != "SSO-Bridge-Plugin" {
		t.Errorf("X-Auth-Source: expected 'SSO-Bridge-Plugin', got '%s'", got)
	}
}

// TestParseTicketData tests ticket data parsing
func TestParseTicketData(t *testing.T) {
	plugin := &SSOBridge{config: &Config{}}

	tests := []struct {
		input    string
		expected map[string]string
		name     string
	}{
		{
			"ID=123;UserName=john",
			map[string]string{"ID": "123", "UserName": "john"},
			"simple case",
		},
		{
			"ID=123;UserName=john.doe;ServiceTicket=ST-12345",
			map[string]string{"ID": "123", "UserName": "john.doe", "ServiceTicket": "ST-12345"},
			"with service ticket",
		},
		{
			"UserName=test%40example.com",
			map[string]string{"UserName": "test@example.com"},
			"url encoded value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.parseTicketData(tt.input)

			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("Key %s: expected '%s', got '%s'", k, v, result[k])
				}
			}
		})
	}
}

// TestRemovePadding tests PKCS7 padding removal
func TestRemovePadding(t *testing.T) {
	plugin := &SSOBridge{config: &Config{}}

	tests := []struct {
		input    []byte
		expected []byte
		name     string
		wantErr  bool
	}{
		{
			[]byte{1, 2, 3, 4, 4, 4, 4, 4},
			[]byte{1, 2, 3, 4},
			"valid padding (4)",
			false,
		},
		{
			[]byte{1, 2, 3, 1},
			[]byte{1, 2, 3},
			"valid padding (1)",
			false,
		},
		{
			[]byte{},
			nil,
			"empty data",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := plugin.removePadding(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if string(result) != string(tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
