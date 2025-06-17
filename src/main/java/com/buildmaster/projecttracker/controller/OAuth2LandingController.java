package com.buildmaster.projecttracker.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
@Slf4j
public class OAuth2LandingController {
    
    /**
     * Handle OAuth2 success redirect with token
     */
    @GetMapping("/")
    public ResponseEntity<Map<String, Object>> handleOAuth2Success(
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String type) {
        
        log.info("OAuth2 landing page accessed - token present: {}, type: {}", 
                token != null, type);
        
        Map<String, Object> response = new HashMap<>();
        
        if (token != null && "oauth2".equals(type)) {
            // OAuth2 successful login
            response.put("success", true);
            response.put("message", "OAuth2 authentication successful!");
            response.put("token", token);
            response.put("type", type);
            response.put("instructions", Map.of(
                "frontend", "Save this token and use it in Authorization header",
                "api", "Use: Authorization: Bearer " + token,
                "test", "Visit /oauth2-test/user with the token"
            ));
        } else {
            // Regular landing page
            response.put("message", "Welcome to ProjectTracker API");
            response.put("oauth2Login", "/oauth2/authorization/google");
            response.put("documentation", "/swagger-ui.html");
            response.put("health", "/api/health");
        }
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * OAuth2 success page for better UX
     */
    @GetMapping("/oauth2/success")
    public ResponseEntity<Map<String, Object>> oauth2SuccessPage(
            @RequestParam(required = false) String token) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "OAuth2 Authentication Successful!");
        
        if (token != null) {
            response.put("token", token);
            response.put("usage", "Use this token in your Authorization header: Bearer " + token);
            response.put("testEndpoint", "/oauth2-test/user");
        }
        
        response.put("nextSteps", Map.of(
            "1", "Copy the token above",
            "2", "Use it in Authorization header for API calls",
            "3", "Test with: GET /oauth2-test/user",
            "4", "Explore API docs at: /swagger-ui.html"
        ));
        
        return ResponseEntity.ok(response);
    }
}