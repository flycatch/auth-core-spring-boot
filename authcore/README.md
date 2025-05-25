# AuthCore

**AuthCore** is a minimal, stateless authentication module designed to plug into any Spring Boot application. It provides JWT-based login, secure token validation, and a configurable request filter.

It is **framework-agnostic** and delegates user and password management entirely to the consuming application.

---

## ✨ Features

- ✅ Stateless JWT authentication  
- ✅ Secure `/auth` endpoint supporting `login`, `register`, `refresh`, and `logout`  
- ✅ Token-based request filtering  
- ✅ Cookie-based refresh token support  
- ✅ Easily configurable via `application.yml`  
- ✅ Pluggable user and password logic  
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
    private String password;

    @Override
    public String getUsername() { return username; }

    @Override
    public String getPassword() { return password; }
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
    public AuthCoreUser save(String username, String encodedPassword) {
        AppUser user = new AppUser(username, encodedPassword);
        return userRepository.save(user);
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

#### Actions supported:
- `login`
- `register`
- `refresh`
- `logout`

#### Login Request
```json
{
  "action": "login",
  "username": "admin",
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

## ✅ Capabilities Matrix

| Capability                     | Provided by AuthCore | Provided by You               |
|-------------------------------|-----------------------|-------------------------------|
| `/auth` endpoint              | ✅ Yes                | ❌ No                         |
| JWT generation & validation   | ✅ Yes                | ❌ No                         |
| User lookup logic             | ❌ No                 | ✅ Yes (`AuthCoreUserService`) |
| Password validation           | ❌ No                 | ✅ Yes (`PasswordEncoder`)     |
| JWT filter integration        | ✅ Yes                | ❌ No                         |

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

```yaml
auth:
  enable-jwt: true
  enable-refresh-token: true
  enable-cookies: true
  cookie-name: AuthRefreshToken
```

---

## 📜 Summary

AuthCore is designed to **streamline JWT authentication** in Spring Boot applications. It provides essential functionality out-of-the-box while giving you full control over:

- User storage
- Password policies
- Role management
- OAuth2 or session extensions

This **separation of responsibilities** makes AuthCore easy to integrate, secure by default, and adaptable to a wide range of projects.

---

## 🧩 License

MIT