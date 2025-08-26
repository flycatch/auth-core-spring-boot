# AuthCore – Spring Boot Authentication Core

AuthCore is a Spring Boot library that provides a configurable authentication layer supporting:

- **JWT** (stateless) authentication with access/refresh tokens
- **Optional refresh-token cookies** (HttpOnly, SameSite, Secure)
- **Session** (stateful) authentication using Spring Session
- **White-label endpoints** for login, refresh, and logout that can be enabled/disabled per application properties
- A simple **SPI** to add custom JWT claims

It is designed to be embedded as a dependency in client apps. Clients choose their auth mode and behavior using only `application.yml`—no code changes required. Clients may also disable the built-in endpoints and implement their own controllers while reusing AuthCore services.

---

## Requirements

- Java 17+
- Spring Boot 3.4.x
- A `UserDetailsService` bean in the client application
- For session mode with JDBC store: `spring-session-jdbc` and a datasource

---

## Installation (Maven)

```xml
<dependency>
  <groupId>io.github.flycatch</groupId>
  <artifactId>authcore</artifactId>
  <version>1.0.0</version>
</dependency>
```

> AuthCore is a library (no `main`), published for use in other Spring Boot apps.

---

## Quick Start

1. Add the dependency above.
2. Ensure your app provides a `UserDetailsService` that can load users by username or email.
3. Pick your auth mode in `application.yml`:
    - **JWT mode** (stateless): `auth.jwt.enabled: true`, `auth.session.enabled: false`
    - **Session mode** (stateful): `auth.session.enabled: true`, `auth.jwt.enabled: false`
4. (JWT mode) Provide a **Base64-encoded 256-bit secret**.

Run the app. The white-label endpoints are auto-configured and available under `/auth/*` when enabled.

---

## Configuration Reference (`application.yml`)

AuthCore is driven entirely by configuration. All properties live under the `auth` prefix.

```yaml
auth:
  jwt:
    enabled: true
    secret: "base64Url_32byte_key_here"
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
    same-site: "Strict"
    max-age: 604800

  logging:
    enabled: true

  endpoints:
    login-enabled: true
    refresh-enabled: true
    logout-enabled: true
```

### Spring infrastructure (example)
```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

  session:
    store-type: jdbc
    jdbc:
      initialize-schema: always
```

---

## What AuthCore Auto-Configures

- **SecurityFilterChain**
- **PasswordEncoder**: `BCryptPasswordEncoder`.
- **AuthCoreConfig**: binds all `auth.*` properties.
- **Controllers** (white-label) if enabled:
    - `POST /auth/login`
    - `POST /auth/refresh` (JWT mode)
    - `POST /auth/logout`
- **Services**
    - `AuthService`

---

## Endpoints (White-Label)

### `POST /auth/login`
```json
{ "username": "testuser", "password": "testpass" }
```

### `POST /auth/refresh` (JWT mode)
```json
{ "refreshToken": "..." }
```

### `POST /auth/logout`
```json
{ "message": "LOGOUT_SUCCESS" }
```

---

## SPI: Add Custom JWT Claims

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

## Using AuthCore With Your Own Controllers

Disable endpoints and call `AuthService` directly.

---

## Security Model Details

- Permit `/auth/**`
- JWT mode uses `JwtAuthFilter`
- Session mode persists in `HttpSession`

---

## DTOs

- `LoginRequest`
- `RefreshRequest`
- `AuthResponse`
- `MessageResponse`

---

## Testing With curl

### JWT mode
```bash
curl -i -X POST "http://localhost:8080/auth/login" -H "Content-Type: application/json" -d '{ "username": "testuser", "password": "testpass" }' -c cookies.txt
```

### Session mode
```bash
curl -i -X POST "http://localhost:8080/auth/login" -H "Content-Type: application/json" -d '{ "username": "testuser", "password": "testpass" }' -c cookies.txt
```


## Versioning and Compatibility

- Java 17
- Spring Boot 3.4.2
- JJWT 0.11.5

---

## Contributing

Fork, clone, build with Maven.

---

## License
AuthCore is licensed under the GNU General Public License v3.0 (GPLv3).
See the [LICENSE](LICENSE) file for details.