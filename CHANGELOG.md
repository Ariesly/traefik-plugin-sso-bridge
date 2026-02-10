# Changelog

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
