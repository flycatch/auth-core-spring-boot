package com.flycatch.authcore.controllers;

import com.flycatch.authcore.service.LoginService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** This controller can be extended to handle login, registration, and other auth-related endpoints.
  * Currently, it serves as a placeholder to ensure the auth module
  * is enabled when the property is set.*/

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth", name = "login", havingValue = "true")
public class LoginController {    private final LoginService loginService;

     @PostMapping("/login")
     public ResponseEntity<LoginResponse> login(
             @RequestBody LoginRequest request,
             HttpServletResponse response
     ) {
         String token = loginService.login(request.getLoginId(), request.getPassword(), response);
         return ResponseEntity.ok(new LoginResponse(token));
     }

     // Request DTO
     @Getter
     public static class LoginRequest {
         @NotBlank
         private String loginId;
         @NotBlank
         private String password;
     }

     // Response DTO
     @Getter
     public static class LoginResponse {
         private final String token;
         public LoginResponse(String token) {
             this.token = token;
         }
     }
}
