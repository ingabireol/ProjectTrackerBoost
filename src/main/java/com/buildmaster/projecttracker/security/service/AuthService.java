package com.buildmaster.projecttracker.security.service;

import com.buildmaster.projecttracker.dto.user.*;
import com.buildmaster.projecttracker.exception.EntityNotFoundException;
import com.buildmaster.projecttracker.model.AuditAction;
import com.buildmaster.projecttracker.model.EntityType;
import com.buildmaster.projecttracker.model.user.AuthProvider;
import com.buildmaster.projecttracker.model.role.Role;
import com.buildmaster.projecttracker.model.role.RoleType;
import com.buildmaster.projecttracker.model.user.User;
import com.buildmaster.projecttracker.repository.RoleRepository;
import com.buildmaster.projecttracker.repository.UserRepository;
import com.buildmaster.projecttracker.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;

    // Use @Lazy to break circular dependency
    @Autowired
    @Lazy
    private JwtService jwtService;

    /**
     * Register a new user
     */
    public UserResponseDto registerUser(UserRegistrationDto registrationDto, String actorName) {
        log.info("Registering new user: {}", registrationDto.getUsername());

        // Check if username already exists
        if (userRepository.existsByUsername(registrationDto.getUsername())) {
            throw new IllegalArgumentException("Username is already taken!");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(registrationDto.getEmail())) {
            throw new IllegalArgumentException("Email is already in use!");
        }

        // Create new user
        User user = new User();
        user.setUsername(registrationDto.getUsername());
        user.setEmail(registrationDto.getEmail());
        user.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
        user.setFirstName(registrationDto.getFirstName());
        user.setLastName(registrationDto.getLastName());
        user.setProvider(AuthProvider.LOCAL);
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);

        // Assign default role (DEVELOPER for local registration)
        Role defaultRole = getOrCreateRole(RoleType.ROLE_DEVELOPER);
        user.addRole(defaultRole);

        // Save user
        User savedUser = userRepository.save(user);

        // Log the registration
        Map<String, Object> payload = createUserAuditPayload(savedUser);
        auditLogService.logAction(
                AuditAction.CREATE,
                EntityType.DEVELOPER,
                savedUser.getId(),
                actorName != null ? actorName : "SYSTEM",
                payload
        );

        log.info("User registered successfully: {}", savedUser.getUsername());
        return convertToUserResponseDto(savedUser);
    }

    /**
     * Authenticate user and generate JWT token
     */
    public JwtResponseDto loginUser(LoginRequestDto loginRequest, String actorName) {
        log.info("Authenticating user: {}", loginRequest.getUsernameOrEmail());

        try {
            // Find user by username or email
            User user = userRepository.findByUsernameOrEmail(loginRequest.getUsernameOrEmail())
                    .orElseThrow(() -> new BadCredentialsException("Invalid username/email or password"));

            // Check if account is enabled
            if (!user.isEnabled()) {
                throw new BadCredentialsException("Account is disabled");
            }

            // Verify password
            if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Invalid username/email or password");
            }

            // Update last login time
            user.updateLastLogin();
            userRepository.updateLastLogin(user.getId(), LocalDateTime.now());

            // Generate JWT response
            JwtResponseDto jwtResponse = jwtService.generateJwtResponse(user);

            // Log successful login
            Map<String, Object> payload = new HashMap<>();
            payload.put("action", "LOGIN_SUCCESS");
            payload.put("username", user.getUsername());
            payload.put("loginTime", LocalDateTime.now());
            payload.put("provider", user.getProvider());

            auditLogService.logAction(
                    AuditAction.UPDATE,
                    EntityType.DEVELOPER,
                    user.getId(),
                    actorName != null ? actorName : user.getUsername(),
                    payload
            );

            log.info("User authenticated successfully: {}", user.getUsername());
            return jwtResponse;

        } catch (BadCredentialsException e) {
            log.warn("Authentication failed for user: {} - {}", loginRequest.getUsernameOrEmail(), e.getMessage());

            // Log failed login attempt
            Map<String, Object> payload = new HashMap<>();
            payload.put("action", "LOGIN_FAILED");
            payload.put("usernameOrEmail", loginRequest.getUsernameOrEmail());
            payload.put("reason", e.getMessage());
            payload.put("timestamp", LocalDateTime.now());

            auditLogService.logAction(
                    AuditAction.UPDATE,
                    EntityType.DEVELOPER,
                    null,
                    actorName != null ? actorName : "ANONYMOUS",
                    payload
            );

            throw new BadCredentialsException("Invalid username/email or password");
        }
    }

    /**
     * Get or create user for OAuth2 login
     */
    public User getOrCreateOAuth2User(String email, String name, String providerId, AuthProvider provider) {
        log.info("Processing OAuth2 user: {} from provider: {}", email, provider);

        // Check if user already exists with this provider and provider ID
        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .orElse(null);

        if (user == null) {
            // Check if user exists with same email but different provider
            user = userRepository.findByEmail(email).orElse(null);

            if (user != null) {
                // Link existing user to OAuth2 provider
                user.setProvider(provider);
                user.setProviderId(providerId);
                log.info("Linked existing user {} to OAuth2 provider: {}", user.getUsername(), provider);
            } else {
                // Create new user for OAuth2
                user = createOAuth2User(email, name, providerId, provider);
                log.info("Created new OAuth2 user: {}", user.getUsername());
            }

            user = userRepository.save(user);
        }

        // Update last login
        user.updateLastLogin();
        userRepository.updateLastLogin(user.getId(), LocalDateTime.now());

        return user;
    }

    /**
     * Create new user from OAuth2 data
     */
    private User createOAuth2User(String email, String name, String providerId, AuthProvider provider) {
        User user = new User();

        // Parse name
        String[] nameParts = name != null ? name.split(" ", 2) : new String[]{"Unknown", "User"};
        String firstName = nameParts[0];
        String lastName = nameParts.length > 1 ? nameParts[1] : "";

        // Generate unique username
        String baseUsername = email.split("@")[0];
        String username = generateUniqueUsername(baseUsername);

        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setProvider(provider);
        user.setProviderId(providerId);
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true);
        user.setPassword(passwordEncoder.encode("oauth2-user-" + System.currentTimeMillis())); // Random password

        // Assign default role for OAuth2 users (CONTRACTOR)
        Role defaultRole = getOrCreateRole(RoleType.ROLE_CONTRACTOR);
        user.addRole(defaultRole);

        return user;
    }

    /**
     * Generate unique username
     */
    private String generateUniqueUsername(String baseUsername) {
        String username = baseUsername;
        int counter = 1;

        while (userRepository.existsByUsername(username)) {
            username = baseUsername + counter;
            counter++;
        }

        return username;
    }

    /**
     * Get or create role
     */
    private Role getOrCreateRole(RoleType roleType) {
        return roleRepository.findByName(roleType.getRoleName())
                .orElseGet(() -> {
                    Role role = new Role(roleType.getRoleName(), roleType.getDescription());
                    return roleRepository.save(role);
                });
    }

    /**
     * Change user password
     */
    public void changePassword(Long userId, PasswordChangeDto passwordChangeDto, String actorName) {
        log.info("Changing password for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));

        // Verify current password
        if (!passwordEncoder.matches(passwordChangeDto.getCurrentPassword(), user.getPassword())) {
            throw new BadCredentialsException("Current password is incorrect");
        }

        // Check if new password matches confirmation
        if (!passwordChangeDto.getNewPassword().equals(passwordChangeDto.getConfirmPassword())) {
            throw new IllegalArgumentException("New password and confirmation do not match");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(passwordChangeDto.getNewPassword()));
        userRepository.save(user);

        // Log password change
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "PASSWORD_CHANGED");
        payload.put("userId", userId);
        payload.put("timestamp", LocalDateTime.now());

        auditLogService.logAction(
                AuditAction.UPDATE,
                EntityType.DEVELOPER,
                userId,
                actorName,
                payload
        );

        log.info("Password changed successfully for user ID: {}", userId);
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
                .collect(java.util.stream.Collectors.toSet()));

        return dto;
    }

    /**
     * Create audit payload for user
     */
    private Map<String, Object> createUserAuditPayload(User user) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("id", user.getId());
        payload.put("username", user.getUsername());
        payload.put("email", user.getEmail());
        payload.put("fullName", user.getFullName());
        payload.put("provider", user.getProvider());
        payload.put("enabled", user.isEnabled());
        payload.put("roles", user.getRoles().stream()
                .map(role -> role.getName())
                .collect(java.util.stream.Collectors.toSet()));
        return payload;
    }
}