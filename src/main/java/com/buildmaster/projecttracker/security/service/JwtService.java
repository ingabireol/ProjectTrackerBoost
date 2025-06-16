package com.buildmaster.projecttracker.security.service;

import com.buildmaster.projecttracker.dto.user.JwtResponseDto;
import com.buildmaster.projecttracker.dto.user.UserResponseDto;
import com.buildmaster.projecttracker.model.user.User;
import com.buildmaster.projecttracker.security.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {
    
    private final JwtUtil jwtUtil;
    
    /**
     * Generate JWT response for authenticated user
     */
    public JwtResponseDto generateJwtResponse(User user) {
        log.debug("Generating JWT response for user: {}", user.getUsername());
        
        // Generate access token
        String accessToken = jwtUtil.generateToken(user);
        
        // Create user response DTO
        UserResponseDto userResponse = convertToUserResponseDto(user);
        
        // Create JWT response
        JwtResponseDto jwtResponse = new JwtResponseDto(
            accessToken,
            jwtUtil.getExpirationTime(),
            userResponse
        );
        
        log.debug("JWT response generated successfully for user: {}", user.getUsername());
        return jwtResponse;
    }
    
    /**
     * Generate refresh token for user
     */
    public String generateRefreshToken(User user) {
        log.debug("Generating refresh token for user: {}", user.getUsername());
        return jwtUtil.generateRefreshToken(user);
    }
    public String generateToken(User user){
        log.debug("Generating token for user: {}", user.getUsername());
        return jwtUtil.generateToken(user);
    }
    
    /**
     * Validate JWT token
     */
    public boolean validateToken(String token) {
        try {
            return jwtUtil.validateToken(token);
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Extract username from JWT token
     */
    public String extractUsername(String token) {
        try {
            return jwtUtil.extractUsername(token);
        } catch (Exception e) {
            log.warn("Failed to extract username from token: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Get token expiration time in milliseconds
     */
    public Long getExpirationTime() {
        return jwtUtil.getExpirationTime();
    }
    
    /**
     * Convert User entity to UserResponseDto
     */
    private UserResponseDto convertToUserResponseDto(User user) {
        UserResponseDto dto = new UserResponseDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setFullName(user.getFullName());
        dto.setEnabled(user.isEnabled());
        dto.setProvider(user.getProvider());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setLastLogin(user.getLastLogin());
        
        // Convert roles to string set
        dto.setRoles(user.getRoles().stream()
                .map(role -> role.getName())
                .collect(Collectors.toSet()));
        
        return dto;
    }
}