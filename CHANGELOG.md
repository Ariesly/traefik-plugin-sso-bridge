# Changelog

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
