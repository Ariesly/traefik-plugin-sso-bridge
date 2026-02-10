// Package traefik_plugin_sso_bridge provides SSO authentication for Traefik
package traefik_plugin_sso_bridge

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds the plugin configuration
type Config struct {
	SecretKey        string   `json:"secretKey,omitempty"`
	CookieName       string   `json:"cookieName,omitempty"`
	CstTokenName     string   `json:"cstTokenName,omitempty"`
	SSOLoginURL      string   `json:"ssoLoginUrl,omitempty"`
	TicketServiceURL string   `json:"ticketServiceUrl,omitempty"`
	ServiceID        string   `json:"serviceId,omitempty"`
	CookieDomain     string   `json:"cookieDomain,omitempty"`
	CookieSecure     bool     `json:"cookieSecure,omitempty"`
	AuthHeaders      []string `json:"authHeaders,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		CookieName:   "SSO_AUTH_TICKET",
		CstTokenName: "cst",
		CookieSecure: false,
		AuthHeaders:  []string{"X-Auth-User", "X-Auth-ID"},
	}
}

// SSOBridge is the main plugin struct
type SSOBridge struct {
	next   http.Handler
	name   string
	config *Config
}

// New creates a new SSO Bridge plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.SecretKey == "" {
		return nil, fmt.Errorf("secretKey is required")
	}

	if len(config.SecretKey) != 8 {
		return nil, fmt.Errorf("secretKey must be exactly 8 characters")
	}

	if config.ServiceID == "" {
		return nil, fmt.Errorf("serviceId is required")
	}

	// Set default CST token parameter name if not provided
	if config.CstTokenName == "" {
		config.CstTokenName = "cst"
	}

	return &SSOBridge{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (s *SSOBridge) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Strategy A: Validate existing cookie (ValidateAT)
	cookie, err := req.Cookie(s.config.CookieName)
	if err == nil && cookie.Value != "" {
		userData, err := s.decryptToken(cookie.Value)
		if err == nil && userData["UserName"] != "" {
			// Authentication successful via cookie
			s.setAuthHeaders(req, userData)
			s.next.ServeHTTP(rw, req)
			return
		}
	}

	// Strategy B: Validate CST token from URL parameter
	cstToken := req.URL.Query().Get(s.config.CstTokenName)
	if cstToken != "" {
		// Step 1: Decrypt CST token from URL
		cstData, err := s.decryptToken(cstToken)
		if err != nil {
			s.redirectToLogin(rw, req)
			return
		}

		// Step 2: Extract ServiceTicket from decrypted CST data
		serviceTicket := cstData["ServiceTicket"]
		if serviceTicket == "" {
			s.redirectToLogin(rw, req)
			return
		}

		// Step 3: Validate ServiceTicket via SOAP
		userData, err := s.validateTicketViaSOAP(serviceTicket)

		// Fallback: If SOAP doesn't return user info, use CST data
		if err == nil && userData["UserName"] == "" {
			userData = cstData
		}

		if err == nil && userData["UserName"] != "" {
			// Authentication successful
			encryptedToken, err := s.encryptToken(userData)
			if err != nil {
				s.redirectToLogin(rw, req)
				return
			}

			// Build clean URL without CST token parameter
			scheme := "http"
			if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}

			host := req.Host
			if host == "" {
				host = req.URL.Host
			}

			// Remove CST token parameter
			q := req.URL.Query()
			q.Del(s.config.CstTokenName)

			// Build redirect URL
			var cleanURL string
			if len(q) > 0 {
				cleanURL = fmt.Sprintf("%s://%s%s?%s", scheme, host, req.URL.Path, q.Encode())
			} else {
				cleanURL = fmt.Sprintf("%s://%s%s", scheme, host, req.URL.Path)
			}

			// Set cookie and redirect
			cookie := &http.Cookie{
				Name:     s.config.CookieName,
				Value:    encryptedToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   s.config.CookieSecure,
				SameSite: http.SameSiteLaxMode,
			}

			if s.config.CookieDomain != "" {
				cookie.Domain = s.config.CookieDomain
			}

			rw.Header().Add("Set-Cookie", cookie.String())
			rw.Header().Set("Location", cleanURL)
			rw.WriteHeader(http.StatusFound)
			return
		}
	}

	// Strategy C: Redirect to SSO login
	s.redirectToLogin(rw, req)
}

// decryptToken decrypts the SSO token using DES-CBC
func (s *SSOBridge) decryptToken(token string) (map[string]string, error) {
	// Base64 decode
	encryptedBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// DES decrypt
	key := []byte(s.config.SecretKey)
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher creation failed: %w", err)
	}

	if len(encryptedBytes)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, key)
	decrypted := make([]byte, len(encryptedBytes))
	mode.CryptBlocks(decrypted, encryptedBytes)

	// Remove PKCS7 padding
	decrypted, err = s.removePadding(decrypted)
	if err != nil {
		return nil, fmt.Errorf("padding removal failed: %w", err)
	}

	// Parse the decrypted string: "ID=xxx;UserName=yyy;ServiceTicket=zzz"
	plainText := string(decrypted)
	return s.parseTicketData(plainText), nil
}

// encryptToken encrypts user data into SSO token using DES-CBC
func (s *SSOBridge) encryptToken(userData map[string]string) (string, error) {
	// Build plain text: "ID=xxx;UserName=yyy"
	var parts []string
	for k, v := range userData {
		parts = append(parts, fmt.Sprintf("%s=%s", k, url.QueryEscape(v)))
	}
	plainText := strings.Join(parts, ";")

	// DES encrypt
	key := []byte(s.config.SecretKey)
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Add PKCS7 padding
	plainBytes := s.addPadding([]byte(plainText), block.BlockSize())

	encrypted := make([]byte, len(plainBytes))
	mode := cipher.NewCBCEncrypter(block, key)
	mode.CryptBlocks(encrypted, plainBytes)

	// Base64 encode
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// ValidateResponse represents the SOAP response structure
type ValidateResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		ValidateResponse struct {
			Result   bool   `xml:"ValidateServiceTicketResult"`
			UserName string `xml:"UserName"`
			ID       string `xml:"ID"`
		} `xml:"ValidateServiceTicketResponse"`
	} `xml:"Body"`
}

// validateTicketViaSOAP validates the ServiceTicket using SOAP
func (s *SSOBridge) validateTicketViaSOAP(ticket string) (map[string]string, error) {
	soapEnvelope := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ValidateServiceTicket xmlns="http://sso.indigox.net/">
      <ticketToken>%s</ticketToken>
      <serviceID>%s</serviceID>
    </ValidateServiceTicket>
  </soap:Body>
</soap:Envelope>`, ticket, s.config.ServiceID)

	req, err := http.NewRequest("POST", s.config.TicketServiceURL, bytes.NewBufferString(soapEnvelope))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://sso.indigox.net/ValidateServiceTicket")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("soap request failed with status: %d", resp.StatusCode)
	}

	var res ValidateResponse
	if err := xml.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("xml decode error: %w", err)
	}

	result := res.Body.ValidateResponse
	if result.Result || result.UserName != "" {
		userData := make(map[string]string)
		userData["UserName"] = result.UserName
		userData["ID"] = result.ID
		return userData, nil
	}

	return nil, fmt.Errorf("ticket validation failed")
}

// parseTicketData parses the decrypted ticket string
func (s *SSOBridge) parseTicketData(plainText string) map[string]string {
	data := make(map[string]string)
	parts := strings.Split(plainText, ";")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			value, _ := url.QueryUnescape(kv[1])
			data[key] = value
		}
	}
	return data
}

// setAuthHeaders sets authentication headers for downstream services
func (s *SSOBridge) setAuthHeaders(req *http.Request, userData map[string]string) {
	if username := userData["UserName"]; username != "" {
		req.Header.Set("X-Auth-User", username)
	}
	if userID := userData["ID"]; userID != "" {
		req.Header.Set("X-Auth-ID", userID)
	}
	req.Header.Set("X-Auth-Source", "SSO-Bridge-Plugin")
}

// redirectToLogin redirects to SSO login page
func (s *SSOBridge) redirectToLogin(rw http.ResponseWriter, req *http.Request) {
	// Build full current URL with scheme and host
	scheme := "http"
	if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Remove CST token parameter to avoid loops
	q := req.URL.Query()
	q.Del(s.config.CstTokenName)

	// Build full URL
	var currentURL string
	if len(q) > 0 {
		currentURL = fmt.Sprintf("%s://%s%s?%s", scheme, host, req.URL.Path, q.Encode())
	} else {
		currentURL = fmt.Sprintf("%s://%s%s", scheme, host, req.URL.Path)
	}

	// Build SSO login URL
	loginURL := fmt.Sprintf("%s?returnURL=%s&service=%s",
		s.config.SSOLoginURL,
		url.QueryEscape(currentURL),
		url.QueryEscape(s.config.ServiceID))

	http.Redirect(rw, req, loginURL, http.StatusFound)
}

// addPadding adds PKCS7 padding
func (s *SSOBridge) addPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// removePadding removes PKCS7 padding
func (s *SSOBridge) removePadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := int(data[length-1])
	if padding > length || padding > des.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	return data[:length-padding], nil
}
