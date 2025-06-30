# AuthCore

**AuthCore** is a flexible, stateless authentication module designed to plug into any Spring Boot application. It provides JWT-based login, refresh token support, role-based access control (RBAC), and optional support for cookies and OAuth2.

It is **framework-agnostic** and delegates user, password, and identity management entirely to the consuming application.

---

## ✨ Features

- ✅ Stateless JWT authentication  
- ✅ Role-Based Access Control (RBAC) (optional via config)  
- ✅ Flexible login using **username or email**  
- ✅ Secure `/auth` endpoint supporting `login`, `register`, `refresh`, and `logout`  
- ✅ Token-based request filtering  
- ✅ Cookie-based refresh token support  
- ✅ Easily configurable via `application.yml`  
- ✅ Pluggable user, email, and password logic  
- ✅ Designed to be extended with OAuth2 or session-based authentication  

---

## 📦 Installation

Add the dependency to your Maven project:

```xml
<dependency>
  <groupId>com.flycatch</groupId>
  <artifactId>authcore</artifactId>
  <version>1.0.0</version>
</dependency>
```

---

## ⚙ Configuration

Add the following configuration to your `application.yml`:

```yaml
auth:
  enable-jwt: true
  enable-session: true
  enable-oauth2: false
  enable-refresh-token: true
  enable-logging: true
  enable-rbac: true              
  enable-cookies: true
  cookie-name: "AuthRefreshToken"
  cookie-http-only: true
  cookie-secure: false
  cookie-same-site: "Strict"
  cookie-max-age: 604800

jwt:
  secret: "Base64EncodedSecretKey=="
  access-token-expiration: 86400000       # 24 hours
  refresh-token-expiration: 604800000     # 7 days
```

Generate a secure Base64-encoded secret key:
```bash
echo -n "your-strong-secret-key" | base64
```

---

## 🧱 Required Beans (Consumer App Responsibilities)

Your application must provide the following:

### 1. `AuthCoreUser` Implementation

```java
public class AppUser implements AuthCoreUser {
    private String username;
    private String email;
    private String password;
    private Set<String> roles;

    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getPassword() { return password; }
    public Set<String> getRoles() { return roles; }
}
```

### 2. `AuthCoreUserService` Implementation

```java
@Service
public class AppUserService implements AuthCoreUserService {

    private final AppUserRepository userRepository;

    public AppUserService(AppUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<? extends AuthCoreUser> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<? extends AuthCoreUser> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public AuthCoreUser save(String username, String email, String encodedPassword) {
        Set<String> roles = new HashSet<>();
        if (userRepository.count() == 0) {
            roles.add("ADMIN");
        } else {
            roles.add("USER");
        }
        return userRepository.save(new AppUser(username, email, encodedPassword, roles));
    }
}
```

### 3. PasswordEncoder Bean

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

---

## 🔐 `/auth` Endpoint

### Method: `POST`

#### Supported Actions
- `login`
- `register`
- `refresh`
- `logout`

#### Register Request

```json
{
  "action": "register",
  "username": "admin",
  "email": "admin@example.com",
  "password": "admin123"
}
```

#### Login Request (Username or Email)

```json
{
  "action": "login",
  "username": "admin",
  "password": "admin123"
}
```
or
```json
{
  "action": "login",
  "email": "admin@example.com",
  "password": "admin123"
}
```

#### Response

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "..."
}
```

Include the access token in future requests:
```http
Authorization: Bearer <accessToken>
```

---

## 🛡 Role-Based Access Control

You can protect your endpoints with `@PreAuthorize`:

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin")
public String adminOnly() {
    return "Welcome, admin!";
}
```

Add method security config:

```java
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {}
```

**Toggle RBAC with `auth.enable-rbac` in `application.yml`:**

- `true`: inject roles into `SecurityContext`, `@PreAuthorize` works
- `false`: skip role injection, only basic authentication applies

---

## ✅ Capabilities Matrix

| Capability                     | Provided by AuthCore | Provided by You                |
|-------------------------------|-----------------------|--------------------------------|
| `/auth` endpoint              | ✅ Yes                | ❌ No                          |
| JWT generation & validation   | ✅ Yes                | ❌ No                          |
| Role-based token injection    | ✅ Optional           | ❌ No                          |
| Flexible login (username/email) | ✅ Yes              | ❌ No                          |
| User lookup logic             | ❌ No                 | ✅ Yes (`AuthCoreUserService`) |
| Password validation           | ❌ No                 | ✅ Yes (`PasswordEncoder`)     |
| User entity persistence       | ❌ No                 | ✅ Yes                         |

---

## 🧪 Example Setup

```java
@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}
```

---

## 📜 Summary

AuthCore is designed to **streamline authentication and authorization** in Spring Boot applications. It provides essential functionality out-of-the-box while giving you full control over:

- User storage (username/email)
- Password policies
- Role management (RBAC optional)
- Token validation & security context
- OAuth2 or session extensions

This **separation of responsibilities** makes AuthCore easy to integrate, secure by default, and adaptable to a wide range of projects.

---

## 🧩 License

MIT