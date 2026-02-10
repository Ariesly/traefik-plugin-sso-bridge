# Quick Start Guide

## 🚀 5-Minute Setup

### Step 1: Create GitHub Repository

```bash
# Create a new repository on GitHub
# Name: traefik-plugin-sso-bridge

# Clone and push this plugin
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/Ariesly/traefik-plugin-sso-bridge.git
git push -u origin main
```

### Step 2: Tag a Release

```bash
git tag v1.0.0
git push origin v1.0.0
```

### Step 3: Configure Traefik

Create `traefik.yml`:

```yaml
experimental:
  plugins:
    sso-bridge:
      moduleName: "github.com/Ariesly/traefik-plugin-sso-bridge"
      version: "v1.0.0"
```

Create `dynamic.yml`:

```yaml
http:
  middlewares:
    my-sso:
      plugin:
        sso-bridge:
          secretKey: "YourKey8"  # ⚠️ Change this!
          cookieName: "SSO_AUTH_TICKET"
          ssoLoginUrl: "http://sso.yourcompany.com/Login.aspx"
          ticketServiceUrl: "http://sso.yourcompany.com/Ticket.asmx"
          serviceId: "your_service_id"
```

### Step 4: Run with Docker Compose

```bash
cd examples/
docker-compose up -d
```

### Step 5: Test

```bash
# Visit protected app
curl http://whoami.localhost

# Should redirect to SSO login
# After login, you'll be authenticated!
```

---

## 📋 Checklist

Before deployment:

- [ ] Change `secretKey` to your actual 8-character DES key
- [ ] Update `serviceId` with your SSO service ID
- [ ] Set `ssoLoginUrl` and `ticketServiceUrl`
- [ ] For HTTPS: set `cookieSecure: true`
- [ ] For domain-wide: set `cookieDomain: ".yourcompany.com"`
- [ ] Tag and push release: `git tag v1.0.0 && git push origin v1.0.0`

---

## 🔧 Customization

### Different Environments

```yaml
# Production
middlewares:
  sso-prod:
    plugin:
      sso-bridge:
        secretKey: "ProdKey8"
        cookieSecure: true
        cookieDomain: ".company.com"

# Development  
middlewares:
  sso-dev:
    plugin:
      sso-bridge:
        secretKey: "DevKey88"
        cookieSecure: false
```

### Multiple Services

```yaml
routers:
  gitea:
    rule: "Host(`git.example.com`)"
    middlewares: [sso-prod]
  
  grafana:
    rule: "Host(`metrics.example.com`)"
    middlewares: [sso-prod]
```

---

## 🐛 Troubleshooting

### Plugin not loading

```bash
# Check Traefik logs
docker logs traefik 2>&1 | grep plugin

# Verify GitHub release exists
curl https://github.com/Ariesly/traefik-plugin-sso-bridge/releases
```

### "Module not found"

- Ensure repository is public
- Verify tag exists: `git tag -l`
- Wait 5-10 minutes for GitHub cache

### Decryption errors

```yaml
# Secret key must be EXACTLY 8 characters
secretKey: "12345678"  # ✅ Valid
secretKey: "short"     # ❌ Invalid
secretKey: "toolong99" # ❌ Invalid
```

---

## 📚 Next Steps

- Read [README.md](../README.md) for full documentation
- Check [examples/](../examples/) for more configurations
- Review [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) for common issues

---

**Need help?** Open an issue on GitHub!
