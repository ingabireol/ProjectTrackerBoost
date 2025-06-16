package com.buildmaster.projecttracker.security.service;

import com.buildmaster.projecttracker.model.user.AuthProvider;
import com.buildmaster.projecttracker.model.user.User;
import com.buildmaster.projecttracker.repository.RoleRepository;
import com.buildmaster.projecttracker.repository.UserRepository;
import com.buildmaster.projecttracker.model.role.Role;
import com.buildmaster.projecttracker.model.role.RoleType;
import com.buildmaster.projecttracker.security.oauth2.OAuth2UserInfo;
import com.buildmaster.projecttracker.security.oauth2.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("Loading OAuth2 user from provider: {}", userRequest.getClientRegistration().getRegistrationId());

        OAuth2User oauth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oauth2User);
        } catch (AuthenticationException ex) {
            log.error("Authentication error processing OAuth2 user: {}", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            log.error("Error processing OAuth2 user: {}", ex.getMessage(), ex);
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oauth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        AuthProvider provider = getAuthProvider(registrationId);

        // Extract user info based on provider
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oauth2User.getAttributes());

        if (!StringUtils.hasText(userInfo.getEmail())) {
            log.error("Email not found from OAuth2 provider: {}", registrationId);
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        // Get or create user (moved the logic here to avoid circular dependency)
        User user = getOrCreateOAuth2User(
                userInfo.getEmail(),
                userInfo.getName(),
                userInfo.getId(),
                provider
        );

        // Update user's last login
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        log.info("OAuth2 user processed successfully: {} from provider: {}", user.getUsername(), provider);

        // Return custom OAuth2User implementation
        return new CustomOAuth2User(user, oauth2User.getAttributes());
    }

    /**
     * Get or create user for OAuth2 login (duplicated to avoid circular dependency)
     */
    private User getOrCreateOAuth2User(String email, String name, String providerId, AuthProvider provider) {
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

    private AuthProvider getAuthProvider(String registrationId) {
        return switch (registrationId.toLowerCase()) {
            case "google" -> AuthProvider.GOOGLE;
            case "github" -> AuthProvider.GITHUB;
            default -> {
                log.error("Unsupported OAuth2 provider: {}", registrationId);
                throw new OAuth2AuthenticationException("Unsupported OAuth2 provider: " + registrationId);
            }
        };
    }
}