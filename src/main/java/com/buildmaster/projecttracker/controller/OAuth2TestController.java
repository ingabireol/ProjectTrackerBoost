package com.buildmaster.projecttracker.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth2-test")
@CrossOrigin(origins = "*")
@Slf4j
public class OAuth2TestController {
    
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getOAuth2User(@AuthenticationPrincipal OAuth2User principal) {
        log.info("OAuth2 user endpoint called");
        
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No authenticated user"));
        }
        
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("name", principal.getName());
        userInfo.put("attributes", principal.getAttributes());
        userInfo.put("authorities", principal.getAuthorities());
        
        return ResponseEntity.ok(userInfo);
    }
    
    @GetMapping("/info")
    public ResponseEntity<Map<String, String>> getOAuth2Info() {
        Map<String, String> info = new HashMap<>();
        info.put("googleLogin", "/oauth2/authorization/google");
        info.put("githubLogin", "/oauth2/authorization/github");
        info.put("userInfo", "/oauth2-test/user");
        info.put("status", "OAuth2 configuration active");
        
        return ResponseEntity.ok(info);
    }
}