// Package traefik_plugin_sso_bridge provides SSO authentication for Traefik
package traefik_plugin_sso_bridge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config holds the plugin configuration
type Config struct {
	SecretKey        string   `json:"secretKey,omitempty"`
	CookieSecret     string   `json:"cookieSecret,omitempty"`
	CookieName       string   `json:"cookieName,omitempty"`
	CstTokenName     string   `json:"cstTokenName,omitempty"`
	SSOLoginURL      string   `json:"ssoLoginUrl,omitempty"`
	TicketServiceURL string   `json:"ticketServiceUrl,omitempty"`
	ServiceID        string   `json:"serviceId,omitempty"`
	CookieDomain     string   `json:"cookieDomain,omitempty"`
	CookieSecure     bool     `json:"cookieSecure,omitempty"`
	CookieMaxAge     int      `json:"cookieMaxAge,omitempty"`
	AuthHeaders      []string `json:"authHeaders,omitempty"`
	SOAPAction       string   `json:"soapAction,omitempty"`
	SOAPNamespace    string   `json:"soapNamespace,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		CookieName:    "SSO_AUTH_TICKET",
		CstTokenName:  "cst",
		CookieSecure:  false,
		CookieMaxAge:  28800,
		AuthHeaders:   []string{"X-Auth-User", "X-Auth-ID"},
		SOAPAction:    "http://sso.indigox.net/ValidateServiceTicket",
		SOAPNamespace: "http://sso.indigox.net/",
	}
}

// SSOBridge is the main plugin struct
type SSOBridge struct {
	next         http.Handler
	name         string
	config       *Config
	httpClient   *http.Client
	cookieAESGCM cipher.AEAD
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

	// Validate cookieSecret length early, before URL checks
	if config.CookieSecret != "" && len(config.CookieSecret) != 32 {
		return nil, fmt.Errorf("cookieSecret must be exactly 32 characters if provided")
	}

	if config.SSOLoginURL == "" {
		return nil, fmt.Errorf("ssoLoginUrl is required")
	}

	if config.TicketServiceURL == "" {
		return nil, fmt.Errorf("ticketServiceUrl is required")
	}

	// Set default CST token parameter name if not provided
	if config.CstTokenName == "" {
		config.CstTokenName = "cst"
	}

	if config.SOAPAction == "" {
		config.SOAPAction = "http://sso.indigox.net/ValidateServiceTicket"
	}

	if config.SOAPNamespace == "" {
		config.SOAPNamespace = "http://sso.indigox.net/"
	}

	var aesKey []byte
	if config.CookieSecret != "" {
		aesKey = []byte(config.CookieSecret)
	} else {
		keyHash := sha256.Sum256([]byte(config.SecretKey))
		aesKey = keyHash[:]
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	return &SSOBridge{
		next:         next,
		name:         name,
		config:       config,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
		cookieAESGCM: aesgcm,
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (s *SSOBridge) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Strategy A: Validate existing cookie
	if s.handleCookieAuth(rw, req) {
		return
	}

	// Strategy B: Validate CST token
	if s.handleCstTokenAuth(rw, req) {
		return
	}

	// Strategy C: Redirect to SSO login
	s.redirectToLogin(rw, req)
}

// handleCookieAuth validates existing cookie authentication
func (s *SSOBridge) handleCookieAuth(rw http.ResponseWriter, req *http.Request) bool {
	cookie, err := req.Cookie(s.config.CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	userData, err := s.decryptCookieData(cookie.Value)
	if err != nil || userData["UserName"] == "" {
		return false
	}

	// Authentication successful via cookie
	s.setAuthHeaders(req, userData)
	s.next.ServeHTTP(rw, req)
	return true
}

// handleCstTokenAuth validates CST token from URL parameter
func (s *SSOBridge) handleCstTokenAuth(rw http.ResponseWriter, req *http.Request) bool {
	cstToken := req.URL.Query().Get(s.config.CstTokenName)
	if cstToken == "" {
		return false
	}

	// Step 1: Decrypt CST token
	cstData, err := s.decryptToken(cstToken)
	if err != nil {
		return false
	}

	// Step 2: Extract ServiceTicket
	serviceTicket := cstData["ServiceTicket"]
	if serviceTicket == "" {
		return false
	}

	// Step 3: Validate ServiceTicket via SOAP
	userData, err := s.validateTicketViaSOAP(req.Context(), serviceTicket)
	if err != nil {
		// Stop infinite redirect loops on network failures by returning 502/504 directly
		if strings.HasPrefix(err.Error(), "network_error") {
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = rw.Write([]byte("502 Bad Gateway: SSO validation service is unavailable"))
			return true
		}
		return false
	}

	// Fallback to CST data safely ONLY since SOAP validation actually succeeded (err == nil)
	// Some legacy SSO implementations return Result=true but an empty UserName.
	// Since the ticket itself was validated by the SOAP endpoint, it is safe to trust
	// the UserName from the (already decrypted and structurally sound) CST token.
	if userData["UserName"] == "" {
		userData = cstData
	}

	if userData["UserName"] == "" {
		return false
	}

	// Authentication successful - set cookie and redirect
	s.setCookieAndRedirect(rw, req, userData)
	return true
}

// setCookieAndRedirect sets authentication cookie and redirects to clean URL
func (s *SSOBridge) setCookieAndRedirect(rw http.ResponseWriter, req *http.Request, userData map[string]string) {
	encryptedToken, err := s.encryptCookieData(userData)
	if err != nil {
		s.redirectToLogin(rw, req)
		return
	}

	cleanURL := s.buildCleanURL(req)
	cookie := s.buildCookie(encryptedToken)

	rw.Header().Add("Set-Cookie", cookie.String())
	rw.Header().Set("Location", cleanURL)
	rw.WriteHeader(http.StatusFound)
}

// buildCleanURL builds URL without CST token parameter
func (s *SSOBridge) buildCleanURL(req *http.Request) string {
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
	if len(q) > 0 {
		return fmt.Sprintf("%s://%s%s?%s", scheme, host, req.URL.Path, q.Encode())
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, req.URL.Path)
}

// buildCookie creates authentication cookie
func (s *SSOBridge) buildCookie(token string) *http.Cookie {
	cookie := &http.Cookie{
		Name:     s.config.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	if s.config.CookieMaxAge > 0 {
		cookie.MaxAge = s.config.CookieMaxAge
	}

	if s.config.CookieDomain != "" {
		cookie.Domain = s.config.CookieDomain
	}

	return cookie
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

// SOAPRequest models the overall SOAP envelope request structure
type SOAPRequest struct {
	XMLName xml.Name `xml:"soap:Envelope"`
	Xmlns   string   `xml:"xmlns:soap,attr"`
	Body    SOAPRequestBody
}

// SOAPRequestBody holds the Body content of the SOAP Request
type SOAPRequestBody struct {
	XMLName xml.Name `xml:"soap:Body"`
	Content interface{}
}

// ValidateServiceTicketRequest models the specific payload for a ValidateServiceTicket query
type ValidateServiceTicketRequest struct {
	XMLName   xml.Name
	Ticket    string `xml:"ticketToken"`
	ServiceID string `xml:"serviceID"`
}

// validateTicketViaSOAP validates the ServiceTicket using SOAP
func (s *SSOBridge) validateTicketViaSOAP(ctx context.Context, ticket string) (map[string]string, error) {
	reqPayload := SOAPRequest{
		Xmlns: "http://schemas.xmlsoap.org/soap/envelope/",
		Body: SOAPRequestBody{
			Content: ValidateServiceTicketRequest{
				XMLName:   xml.Name{Space: s.config.SOAPNamespace, Local: "ValidateServiceTicket"},
				Ticket:    ticket,
				ServiceID: s.config.ServiceID,
			},
		},
	}

	xmlBytes, err := xml.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal soap request: %w", err)
	}

	soapEnvelope := append([]byte(xml.Header), xmlBytes...)

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.TicketServiceURL, bytes.NewReader(soapEnvelope))
	if err != nil {
		return nil, fmt.Errorf("network_error: request creation failed: %w", err)
	}

	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", s.config.SOAPAction)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network_error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("network_error: soap request failed with status: %d", resp.StatusCode)
	}

	var res ValidateResponse
	// Limit response body to 1 MB to prevent memory exhaustion from malicious servers
	limitedBody := io.LimitReader(resp.Body, 1<<20)
	if err := xml.NewDecoder(limitedBody).Decode(&res); err != nil {
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
	// Default header names if config is malformed or empty
	userHeader := "X-Auth-User"
	idHeader := "X-Auth-ID"

	// Map configured headers if available
	if len(s.config.AuthHeaders) > 0 {
		userHeader = s.config.AuthHeaders[0]
	}
	if len(s.config.AuthHeaders) > 1 {
		idHeader = s.config.AuthHeaders[1]
	}

	if username := userData["UserName"]; username != "" {
		req.Header.Set(userHeader, username)
	}
	if userID := userData["ID"]; userID != "" {
		req.Header.Set(idHeader, userID)
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

	// Build SSO login URL gracefully handling existing query params
	separator := "?"
	if strings.Contains(s.config.SSOLoginURL, "?") {
		separator = "&"
	}

	loginURL := fmt.Sprintf("%s%sreturnURL=%s&service=%s",
		s.config.SSOLoginURL,
		separator,
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
	// padding == 0 is invalid PKCS7; also guard against out-of-range values
	if padding == 0 || padding > length || padding > des.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	// Use constant-time comparison to prevent timing oracle attacks
	paddingBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	if subtle.ConstantTimeCompare(data[length-padding:], paddingBytes) != 1 {
		return nil, fmt.Errorf("invalid padding byte")
	}

	return data[:length-padding], nil
}

// encryptCookieData encrypts internal session data using AES-GCM
func (s *SSOBridge) encryptCookieData(userData map[string]string) (string, error) {
	var parts []string
	for k, v := range userData {
		parts = append(parts, fmt.Sprintf("%s=%s", k, url.QueryEscape(v)))
	}
	plainText := strings.Join(parts, ";")

	nonce := make([]byte, s.cookieAESGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := s.cookieAESGCM.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptCookieData decrypts internal session data using AES-GCM
func (s *SSOBridge) decryptCookieData(token string) (map[string]string, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	nonceSize := s.cookieAESGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := s.cookieAESGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return s.parseTicketData(string(plaintext)), nil
}
