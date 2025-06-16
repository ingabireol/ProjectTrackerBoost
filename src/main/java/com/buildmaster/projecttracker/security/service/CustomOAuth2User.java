package com.buildmaster.projecttracker.security.service;

import com.buildmaster.projecttracker.model.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

/**
 * Custom OAuth2User implementation that wraps our User entity
 * This allows us to access our User object from OAuth2 authentication
 */
public class CustomOAuth2User implements OAuth2User {

    private final User user;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities();
    }

    @Override
    public String getName() {
        return user.getUsername();
    }

    /**
     * Get the wrapped User entity
     * @return User entity
     */
    public User getUser() {
        return user;
    }

    /**
     * Get user ID
     * @return User ID
     */
    public Long getUserId() {
        return user.getId();
    }

    /**
     * Get user email
     * @return User email
     */
    public String getEmail() {
        return user.getEmail();
    }

    /**
     * Get user's full name
     * @return Full name
     */
    public String getFullName() {
        return user.getFullName();
    }
}