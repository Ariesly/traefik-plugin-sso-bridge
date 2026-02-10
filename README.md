# Traefik Plugin: SSO Bridge

[![Build Status](https://github.com/Ariesly/traefik-plugin-sso-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Ariesly/traefik-plugin-sso-bridge/actions)
[![Go Report](https://goreportcard.com/badge/github.com/Ariesly/traefik-plugin-sso-bridge)](https://goreportcard.com/report/github.com/Ariesly/traefik-plugin-sso-bridge)
[![License](https://img.shields.io/github/license/Ariesly/traefik-plugin-sso-bridge)](LICENSE)

A Traefik middleware plugin that bridges legacy SSO systems to modern applications using DES encryption and SOAP validation.

## Features

- ✅ **DES-CBC Decryption** - Decrypt legacy SSO cookies
- ✅ **CST Token Handling** - Extract and validate Service Tickets from CST tokens  
- ✅ **SOAP Ticket Validation** - Validate tickets via SOAP web service
- ✅ **Cookie Management** - Auto-generate cookies after ticket validation
- ✅ **Triple Validation Strategy** - Cookie → CST Token → Login redirect
- ✅ **Header Injection** - Inject user info for downstream apps

---

## Installation

### 1. Static Configuration

Add to your `traefik.yml`:

```yaml
experimental:
  plugins:
    sso-bridge:
      moduleName: "github.com/Ariesly/traefik-plugin-sso-bridge"
      version: "v1.0.0"
```

### 2. Dynamic Configuration

Configure the middleware in `dynamic.yml`:

```yaml
http:
  middlewares:
    my-sso-bridge:
      plugin:
        sso-bridge:
          secretKey: "YourKey8"           # Must be 8 characters
          cookieName: "SSO_AUTH_TICKET"
          cstTokenName: "cst"             # URL parameter name (default: "cst")
          ssoLoginUrl: "http://sso.example.com/Login.aspx"
          ticketServiceUrl: "http://sso.example.com/Ticket.asmx"
          serviceId: "your_service_id"
          cookieDomain: ".example.com"    # Optional
          cookieSecure: true              # Use true for HTTPS
```

### 3. Apply to Routes

```yaml
http:
  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      service: my-service
      middlewares:
        - my-sso-bridge@file
```

---

## Configuration Options

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `secretKey` | string | ✅ Yes | - | 8-character DES key |
| `cookieName` | string | ❌ No | `SSO_AUTH_TICKET` | Cookie name |
| `cstTokenName` | string | ❌ No | `cst` | URL parameter name for CST token |
| `ssoLoginUrl` | string | ✅ Yes | - | SSO login page URL |
| `ticketServiceUrl` | string | ✅ Yes | - | SOAP validation endpoint |
| `serviceId` | string | ✅ Yes | - | Service ID in SSO system |
| `cookieDomain` | string | ❌ No | - | Cookie domain (e.g., `.example.com`) |
| `cookieSecure` | bool | ❌ No | `false` | Enable secure flag (HTTPS) |

---

## How It Works

### Authentication Flow

```
1. User accesses https://app.example.com/dashboard
   ↓
2. Traefik intercepts request
   ↓
3. SSO Bridge Plugin checks:
   ├─ A. Valid cookie? → Pass to app
   ├─ B. Valid CST token (e.g., ?cst=xxx)? → Decrypt → Extract ST → Validate → Set cookie → Redirect
   └─ C. Neither? → Redirect to SSO login
   ↓
4. App receives X-Auth-User header
```

### CST Token Processing

```
URL: ?cst=<encrypted_token>
  ↓
Step 1: Decrypt CST token
  Result: {ID: "123", UserName: "john", ServiceTicket: "ST-12345"}
  ↓
Step 2: Extract ServiceTicket
  ServiceTicket: "ST-12345"
  ↓
Step 3: Validate via SOAP
  POST /Ticket.asmx
  <ValidateServiceTicket>
    <ticketToken>ST-12345</ticketToken>
    <serviceID>your_service_id</serviceID>
  </ValidateServiceTicket>
  ↓
Step 4: Set cookie and redirect to clean URL
  Set-Cookie: SSO_AUTH_TICKET=<encrypted_user_data>
  Location: https://app.example.com/dashboard
```

---

## Examples

### Docker Compose

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v3.0
    command:
      - "--experimental.plugins.sso-bridge.moduleName=github.com/Ariesly/traefik-plugin-sso-bridge"
      - "--experimental.plugins.sso-bridge.version=v1.0.0"
    ports:
      - "80:80"
    volumes:
      - ./dynamic.yml:/etc/traefik/dynamic.yml

  gitea:
    image: gitea/gitea:latest
    environment:
      - GITEA__service__ENABLE_REVERSE_PROXY_AUTHENTICATION=true
      - GITEA__service__REVERSE_PROXY_AUTHENTICATION_USER=X-Auth-User
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.gitea.rule=Host(`git.localhost`)"
      - "traefik.http.routers.gitea.middlewares=my-sso-bridge@file"
```

---

## Development

### Run Tests

```bash
go test -v
```

### Build

```bash
go build
```

---

## Troubleshooting

### CST Token Not Recognized

Check the `cstTokenName` configuration matches your URL parameter:

```yaml
# URL: ?cst=xxx
cstTokenName: "cst"  # ✅ Correct

# URL: ?token=xxx  
cstTokenName: "token"  # ✅ Must match
```

### Cookie Not Set

Ensure proper domain and secure settings:

```yaml
# HTTPS environment
cookieSecure: true
cookieDomain: ".example.com"

# HTTP development
cookieSecure: false
cookieDomain: ""
```

---

## License

MIT License

---

## Credits

Created to bridge legacy SSO systems with modern microservices architecture.

**Repository**: https://github.com/Ariesly/traefik-plugin-sso-bridge
