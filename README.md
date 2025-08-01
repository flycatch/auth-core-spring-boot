# AuthCore - Spring Boot Authentication Core Library

`authcore` is a modular and extensible authentication library for Spring Boot projects. It supports both **JWT-based** and **Session-based** authentication with refresh token support, cookies, and fully pluggable SPI interfaces.

---

## 📦 Local Dependency Setup (Development Only)

To use the library locally in your Spring Boot project:

### 1. Clone the repository

```bash
git clone https://github.com/flycatch/auth-core-spring-boot.git
```

### 2. Install it into your local Maven repository

```bash
cd auth-core-spring-boot
mvn clean install
```

### 3. Add the dependency in your project’s `pom.xml`

```xml
<dependency>
  <groupId>io.github.flycatch</groupId>
  <artifactId>authcore</artifactId>
  <version>0.7.5-SNAPSHOT</version>
</dependency>
```

---

## ⚙️ Configuration (`application.yml`)

```yaml
auth:
  jwt:
    enabled: true
    secret: "Gm/dZyJQfEJxC0tDdHlQYxZxVa4vX2RkYXJrbmV0VmFsaWRLZXlNYWtlU3VyZQ=="
    access-token-expiration: 86400000        # 24 hours
    refresh-token-expiration: 604800000      # 7 days

  session:
    enabled: true
    store-type: jdbc                         # Supported: jdbc, none

  refresh-token:
    enabled: true

  logging:
    enabled: true

  cookies:
    enabled: true
    name: "AuthRefreshToken"
    http-only: true
    secure: false                            # Set true in production with HTTPS
    same-site: "Strict"
    max-age: 604800
```

---

## 🔌 Required SPI Implementations

### 1. `AuthCoreUserService`

```java
@Service
public class MyUserService implements AuthCoreUserService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public Optional<Object> findByUsername(String username) {
        return Optional.ofNullable(userRepository.findByUsername(username));
    }

    @Override
    public Optional<Object> findByEmail(String email) {
        return Optional.ofNullable(userRepository.findByEmail(email));
    }

    @Override
    public Object save(String username, String email, String encodedPassword) {
        return userRepository.save(new User(username, email, encodedPassword));
    }
}
```

### 2. `JwtClaimsProvider`

```java
@Component
public class MyClaimsProvider implements JwtClaimsProvider {

    @Override
    public String extractUsername(Object user) {
        return ((User) user).getUsername();
    }

    @Override
    public String extractPassword(Object user) {
        return ((User) user).getPassword();
    }

    @Override
    public Map<String, Object> extractClaims(Object user) {
        User u = (User) user;
        return Map.of("username", u.getUsername(), "email", u.getEmail());
    }

    @Override
    public Collection<? extends GrantedAuthority> extractAuthorities(Map<String, Object> claims) {
        return Collections.emptyList(); // Add role mapping if needed
    }
}
```

---

## 🚀 Sample Usage in Controller

```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req,
                                   HttpServletResponse response,
                                   HttpServletRequest request) {
        return ResponseEntity.ok(authService.authenticate(req.getLoginId(), req.getPassword(), response, request));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        return ResponseEntity.ok(authService.register(req.getUsername(), req.getEmail(), req.getPassword()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue("AuthRefreshToken") String token,
                                     HttpServletResponse response) {
        return ResponseEntity.ok(authService.refreshAccessToken(token, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        return ResponseEntity.ok(authService.logout(response));
    }
}
```

---

## ✨ Features

| Feature             | Support  |
|---------------------|----------|
| JWT authentication  | ✅       |
| Session authentication (JDBC) | ✅       |
| Refresh token support | ✅       |
| Cookie-based refresh | ✅       |
| SPI-based integration | ✅       |
| Modular Spring Boot setup | ✅       |
| Auto-configuration   | ✅       |

---

## 📚 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).


---

## 🌐 Global Dependency (Coming Soon)

Support for Maven Central / GitHub Packages will be documented here once deployed.