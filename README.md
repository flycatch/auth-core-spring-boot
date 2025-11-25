# AuthCore – Spring Boot Authentication Core

AuthCore is a Spring Boot authentication library that provides a fully configurable, pluggable security layer supporting:

- JWT (stateless) authentication with access and refresh tokens
- Optional HttpOnly refresh-token cookies (Secure, SameSite=None supported)
- Stateful authentication via Spring Session (JDBC/Redis)
- Two-Factor Authentication (email/SMS OTP)
- OAuth2 Login (Google, GitHub, etc.)
- OAuth2 Authorization-Code Flow (secure backend-to-backend token exchange)
- RBAC with role/permission expansion
- White-label authentication endpoints
- SPI hooks for custom claims, user provisioning, OTP delivery
- Automatic validation of auth-related configuration on startup

AuthCore is designed to be embedded inside client applications.
All behavior is controlled through `application.yml` without modifying AuthCore’s code.

---

## Requirements

- Java 17+
- Spring Boot 3.4.x+
- A `UserDetailsService` bean in the client application
- For session mode: `spring-session-jdbc` (or Redis) + datasource
- For OAuth2 login: Spring Security OAuth2 client configuration
- For OTP: custom `OtpSender` bean (optional)

---

## Installation (Maven)

```xml
<dependency>
  <groupId>io.github.flycatch</groupId>
  <artifactId>authcore</artifactId>
  <version>1.0.1</version>
</dependency>
```

AuthCore does not include a `main` class; it is consumed by other Spring Boot applications.

---

## Quick Start

- Add the Maven dependency
- Implement `UserDetailsService` to load users by username or email
- Provide a `UserDetails` implementation with roles/permissions
- Pick your authentication mode in `application.yml`
    - **JWT mode:** `auth.jwt.enabled: true`, `auth.session.enabled: false`
    - **Session mode:** `auth.session.enabled: true`, `auth.jwt.enabled: false`
    - **Hybrid mode:** both enabled
- Provide a 32-byte JWT secret (JWT mode)
- Configure optional features such as cookies, OTP, OAuth2 login, and authorization-code mode
- Run the application; AuthCore registers all `/auth/*` endpoints automatically

---

## Configuration Reference (application.yml)

```yaml
auth:
  jwt:
    enabled: true
    secret: "base64OrPlaintext_32byte_key"
    access-token-expiration: 86400000
    refresh-token-expiration: 604800000
    refresh-token-enabled: true

  session:
    enabled: false

  cookies:
    enabled: true
    name: "AuthRefreshToken"
    http-only: true
    secure: false
    same-site: "None"
    max-age: 604800

  logging:
    enabled: true

  endpoints:
    login-enabled: true
    refresh-enabled: true
    logout-enabled: true

  two-factor:
    enabled: false
    type: EMAIL
    length: 6
    alphanumeric: false
    expiry-seconds: 300

  oauth2:
    enabled: false
    success-redirect: "http://localhost:8080/after-login"
    failure-redirect: "http://localhost:8080/login-failed"
    issue-jwt: true
    include-authorities: true
    set-refresh-cookie: true
    append-tokens-in-redirect: false
    auto-provision-enabled: true
    default-role: "ROLE_USER"

    authorization-code-enabled: true
    code-param: "code"
    code-length: 40
    code-ttl-seconds: 300
```

### Example Spring configuration

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

  security:
    oauth2:
      client:
        registration:
          google:
            client-id: "your-client-id"
            client-secret: "your-client-secret"
            scope: [openid, email, profile]
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"

  session:
    store-type: jdbc
    jdbc:
      initialize-schema: always
```

---

## What AuthCore Auto-Configures

- Security filter chain
- BCrypt password encoder
- Config binding (`auth.*`)
- White-label controllers:
    - `/auth/login`
    - `/auth/verify-otp`
    - `/auth/refresh`
    - `/auth/logout`
    - `/auth/oauth2/providers`
    - `/auth/oauth2/exchange`
- Services:
    - `AuthService`
    - `JwtService`
    - `OtpService`
    - `RbacService`

Endpoints are enabled or disabled through `auth.endpoints.*`.

---

## Endpoints (White-Label)

### `POST /auth/login`
```json
{ "loginId": "user", "password": "pass" }
```

OTP required:
```json
{ "message": "OTP_REQUIRED", "delivery": "EMAIL" }
```

JWT mode:
```json
{ "accessToken": "...", "refreshToken": "...", "message": "JWT_AUTHENTICATED" }
```

Session mode:
```json
{ "message": "SESSION_AUTHENTICATED" }
```

---

### `POST /auth/verify-otp`
```json
{ "loginId": "user", "otp": "123456" }
```

Returns normal login response.

---

### `POST /auth/refresh`
```json
{ "refreshToken": "..." }
```

---

### `POST /auth/logout`
```json
{ "message": "LOGOUT_SUCCESS" }
```

---

### `GET /auth/oauth2/providers`
Lists available OAuth2 providers.

---

### `POST /auth/oauth2/exchange`
```json
{ "code": "XYZ" }
```

Failure:
```json
{ "message": "UNAUTHORIZED" }
```

---

## SPI: Custom JWT Claims

```java
@Component
public class AppJwtClaimsProvider implements JwtClaimsProvider {
  @Override
  public Map<String, Object> extractClaims(UserDetails user) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", user.getUsername());
    return claims;
  }
}
```

---

## SPI: User Provisioning (OAuth2)

```java
@Primary
@Component
public class AppUserProvisioner implements UserProvisioner {
  @Override
  public ProvisionResult provisionIfAbsent(OAuth2UserProfile profile) {
    return ProvisionResult.createdWithAuthorities(Set.of("ROLE_USER"));
  }
}
```

---

## SPI: Custom OTP Sender

```java
@Primary
@Component
public class SmtpOtpSender implements OtpSender {
  @Override
  public void sendOtp(String username, String destination, String otpCode) {
    // implementation here
  }
}
```

---

## Security Model Details

- `/auth/**` is public
- All other routes require authentication
- JWT mode uses `Authorization: Bearer <token>`
- Session mode uses HttpSession
- RBAC expands roles and permissions defined in config

---

## DTOs

- `LoginRequest`
- `OtpVerifyRequest`
- `RefreshRequest`
- `OAuth2ExchangeRequest`
- `AuthResponse`
- `MessageResponse`

---

## Testing With curl

### Login
```bash
curl -X POST http://localhost:8080/auth/login   -H "Content-Type: application/json"   -d '{"loginId":"testuser","password":"testpass"}'
```

### Refresh
```bash
curl -X POST http://localhost:8080/auth/refresh   -H "Content-Type: application/json"   -d '{"refreshToken":"XYZ"}'
```

### OAuth2 exchange
```bash
curl -X POST http://localhost:8080/auth/oauth2/exchange   -H "Content-Type: application/json"   -d '{"code":"XYZ"}'
```

---

## Version Compatibility

- Java 17+
- Spring Boot 3.4.x
- JJWT 0.11.5

---

## License

AuthCore is licensed under the GNU General Public License v3.0 (GPLv3).  
See the LICENSE file for full details.