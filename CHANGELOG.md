# Changelog

## [v1.3.0] - 2026-03-17

### Security & Reliability
- **Strict Verification Validation**: Enforced hard start-up requirement of `ssoLoginUrl` and `ticketServiceUrl` in configuration, immediately failing loud if missing to prevent deployment failures at runtime.
- **Timing Attack Mitigation**: Upgraded legacy PKCS#7 block parser to utilize standard `crypto/subtle.ConstantTimeCompare()`, preventing padding-oracle side-channel attacks globally.
- **CST Secure Fallback**: Re-introduced the legacy fallback to extract UserNames from validated CST context when absent from the primary XML response.
- **DOS Protection**: Prevented deliberate memory exhaustion (DoS attacks) by wrapping XML parsing bounds via `io.LimitReader` within `validateTicketViaSOAP`.
- **Persistent State Control**: Formalized `cookieMaxAge` setting (default: 8 hours) to explicitly enforce expiration rather than risking unexpected session persistence over multiple tabs.

---

## [v1.2.0] - 2026-03-12

### Security
- **Critical Vulnerability Fix**: Upgraded internal Cookie encryption from legacy DES-CBC to modern **AES-256-GCM**, securely hashing the 8-byte secret key with SHA-256 to leverage authenticated encryption.
- **XML Injection Defense**: Hardened SOAP payload generation by replacing manual string formatting with native `xml.Marshal` and strong struct modeling.
- **Padding Oracle Defense**: Hardened the legacy PKCS7 padding parsing loop to reject malicious blocks explicitly.

### Changed
- **Performance Enhancement**: Instantiated a global HTTP connection pool (`http.Client`) during middleware creation instead of per-request, significantly reducing CPU load and TCP handshake overhead.
- **Stability Improvement**: Improved CST Token validation handling to proactively return HTTP 502/504 on network/upstream XML failures, preventing infinite redirect loop conditions.
- **Bug Fix**: Fixed a bug where `ssoLoginUrl` query parameters were not respected properly when appending the `returnURL` redirect.

### Added
- Created `soapAction` configuration (default: `http://sso.indigox.net/ValidateServiceTicket`) enabling custom endpoint routing.
- Created `soapNamespace` configuration (default: `http://sso.indigox.net/`) eliminating hardcoded domain constraints.
- Fixed a bug where `authHeaders` overriding did correctly propagate configuration downward. Added unit test validation for edge-case boundaries.

---

## [v1.1.0] - 2026-02-08

### Changed
- **Code Quality**: Refactored `ServeHTTP` to reduce cyclomatic complexity from 18 to 3
  - Extracted `handleCookieAuth()` method for cookie validation
  - Extracted `handleCstTokenAuth()` method for CST token validation
  - Extracted `setCookieAndRedirect()` method for cookie setting and redirection
  - Extracted `buildCleanURL()` helper for URL construction
  - Extracted `buildCookie()` helper for cookie creation
  - Improved code readability and maintainability

### Added
- 7 new unit tests for extracted methods:
  - `TestHandleCookieAuth`
  - `TestHandleCookieAuth_NoCookie`
  - `TestBuildCleanURL` (with 4 scenarios)
  - `TestBuildCleanURL_HTTPS`
  - `TestBuildCookie`

### Performance
- No performance impact - purely structural improvements
- All existing functionality remains identical

**Code Quality Metrics**:
```
Before (v1.0.0):
- ServeHTTP cyclomatic complexity: 18 ❌

After (v1.1.0):
- ServeHTTP cyclomatic complexity: 3 ✅
- handleCookieAuth complexity: 4 ✅
- handleCstTokenAuth complexity: 8 ✅
- Go Report Card: A+ ✅
```

---

## [v1.0.0] - 2026-02-08

### Fixed
- **Critical**: Fixed authentication headers not being passed to upstream applications
  - Changed `setAuthHeaders` to modify request headers (`req.Header`) instead of response headers (`rw.Header`)
  - Now headers like `X-Auth-User`, `X-Auth-ID` are correctly received by upstream apps (Gitea, Whoami, etc.)
  
**Technical Details**:
```go
// Before (v0.0.5) - WRONG ❌
func (s *SSOBridge) setAuthHeaders(rw http.ResponseWriter, userData map[string]string) {
    rw.Header().Set("X-Auth-User", username)  // ❌ Response header, not passed to upstream
}

// After (v1.0.0) - CORRECT ✅
func (s *SSOBridge) setAuthHeaders(req *http.Request, userData map[string]string) {
    req.Header.Set("X-Auth-User", username)   // ✅ Request header, passed to upstream
}
```

### Added
- New test case `TestSetAuthHeaders` to verify header propagation
- Enhanced `TestServeHTTP_ValidCookie` to check received headers

**Verification**:
```bash
# Test with whoami
curl http://whoami.localhost -H "Cookie: SSO_AUTH_TICKET=xxx"

# Should see in response:
# X-Auth-User: john.doe
# X-Auth-ID: 12345
# X-Auth-Source: SSO-Bridge-Plugin
```

---

## [v0.0.5] - 2026-02-08

### Changed
- **BREAKING**: Renamed `cstTokenName` to `cstTokenName`
- **BREAKING**: Changed default parameter name from `ticket` to `cst`
- Removed all debug logging for production use
- Cleaned up code structure

### Added
- Comprehensive unit test suite with 15+ test cases
- Better error handling in CST token processing
- Improved documentation

### Fixed
- CST token extraction and validation workflow
- Cookie setting with proper redirect
- ServiceTicket extraction from decrypted CST data

**Migration Guide**:
```yaml
# Old configuration (v0.0.1)
cstTokenName: "ticket"

# New configuration (v0.0.5)
cstTokenName: "cst"
```

---

## [v0.0.1] - 2026-02-06

### Initial Release
- DES-CBC decryption for legacy SSO cookies
- SOAP ticket validation
- Cookie management  
- Triple validation strategy
- Traefik v3 plugin support
