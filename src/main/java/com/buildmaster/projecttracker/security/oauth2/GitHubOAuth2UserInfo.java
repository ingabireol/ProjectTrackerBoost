package com.buildmaster.projecttracker.security.oauth2;

import java.util.Map;

class GitHubOAuth2UserInfo implements OAuth2UserInfo {
    private final Map<String, Object> attributes;
    
    public GitHubOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
    
    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }
    
    @Override
    public String getName() {
        String name = (String) attributes.get("name");
        if (name != null && !name.trim().isEmpty()) {
            return name;
        }
        
        // Fallback to login (username)
        String login = (String) attributes.get("login");
        return login != null ? login : "Unknown User";
    }
    
    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
    
    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}