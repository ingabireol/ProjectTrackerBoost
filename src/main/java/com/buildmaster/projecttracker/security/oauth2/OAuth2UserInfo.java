package com.buildmaster.projecttracker.security.oauth2;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import java.util.Map;

// OAuth2 User Info interface
public interface OAuth2UserInfo {
    String getId();
    String getName();
    String getEmail();
    String getImageUrl();
}

// Factory class to create OAuth2UserInfo instances


// GitHub OAuth2 User Info implementation
