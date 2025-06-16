package com.buildmaster.projecttracker.controller;

import com.buildmaster.projecttracker.dto.user.*;
import com.buildmaster.projecttracker.model.user.User;
import com.buildmaster.projecttracker.security.service.AuthService;
import com.buildmaster.projecttracker.security.service.CustomOAuth2User;
import com.buildmaster.projecttracker.security.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")
@Tag(name = "Authentication", description = "Authentication and authorization operations")
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Register a new user with local authentication")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully",
                    content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Invalid registration data"),
            @ApiResponse(responseCode = "409", description = "Username or email already exists")
    })
    public ResponseEntity<UserResponseDto> registerUser(
            @Valid @RequestBody @Parameter(description = "User registration details") UserRegistrationDto registrationDto,
            HttpServletRequest request) {

        log.info("User registration attempt: {}", registrationDto.getUsername());

        String actorName = getActorName(request);
        UserResponseDto user = authService.registerUser(registrationDto, actorName);

        log.info("User registered successfully: {}", user.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(schema = @Schema(implementation = JwtResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials"),
            @ApiResponse(responseCode = "403", description = "Account disabled or locked")
    })
    public ResponseEntity<JwtResponseDto> loginUser(
            @Valid @RequestBody @Parameter(description = "Login credentials") LoginRequestDto loginRequest,
            HttpServletRequest request) {

        log.info("Login attempt for user: {}", loginRequest.getUsernameOrEmail());

        String actorName = getActorName(request);
        JwtResponseDto jwtResponse = authService.loginUser(loginRequest, actorName);

        log.info("User logged in successfully: {}", loginRequest.getUsernameOrEmail());
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change password", description = "Change password for authenticated user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid password data"),
            @ApiResponse(responseCode = "401", description = "Current password incorrect")
    })
    public ResponseEntity<Map<String, String>> changePassword(
            @Valid @RequestBody @Parameter(description = "Password change details") PasswordChangeDto passwordChangeDto,
            @AuthenticationPrincipal org.springframework.security.core.userdetails.UserDetails userDetails,
            HttpServletRequest request) {

        log.info("Password change attempt for user: {}", userDetails.getUsername());

        // Get user ID from authenticated user
        User user = (User) userDetails;
        String actorName = getActorName(request, user.getUsername());

        authService.changePassword(user.getId(), passwordChangeDto, actorName);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Password changed successfully");

        log.info("Password changed successfully for user: {}", userDetails.getUsername());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/oauth2/success")
    @Operation(summary = "OAuth2 success callback", description = "Handle successful OAuth2 authentication")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OAuth2 authentication successful",
                    content = @Content(schema = @Schema(implementation = JwtResponseDto.class))),
            @ApiResponse(responseCode = "500", description = "OAuth2 authentication processing failed")
    })
    public ResponseEntity<JwtResponseDto> oauth2Success(
            @AuthenticationPrincipal OAuth2User oauth2User,
            HttpServletResponse response) throws IOException {

        log.info("OAuth2 authentication success for user: {}", oauth2User.getName());

        try {
            // Get the custom OAuth2User that contains our User entity
            CustomOAuth2User customUser = (CustomOAuth2User) oauth2User;

            // Generate JWT for the OAuth2 user
            JwtResponseDto jwtResponse = jwtService.generateJwtResponse(customUser.getUser());

            log.info("JWT generated for OAuth2 user: {}", customUser.getUser().getUsername());
            return ResponseEntity.ok(jwtResponse);

        } catch (Exception e) {
            log.error("Error processing OAuth2 success: {}", e.getMessage(), e);
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "OAuth2 Authentication Failed");
            errorResponse.put("message", e.getMessage());

            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Authentication failed");
            return null;
        }
    }

    @GetMapping("/oauth2/error")
    @Operation(summary = "OAuth2 error callback", description = "Handle OAuth2 authentication errors")
    public ResponseEntity<Map<String, String>> oauth2Error(
            @RequestParam(required = false) String message) {

        log.warn("OAuth2 authentication error: {}", message);

        Map<String, String> response = new HashMap<>();
        response.put("error", "OAuth2 Authentication Failed");
        response.put("message", message != null ? message : "Unknown error occurred");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @PostMapping("/validate-token")
    @Operation(summary = "Validate JWT token", description = "Check if JWT token is valid and not expired")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token is valid"),
            @ApiResponse(responseCode = "401", description = "Token is invalid or expired")
    })
    public ResponseEntity<Map<String, Object>> validateToken(
            @RequestHeader("Authorization") @Parameter(description = "Bearer JWT token") String authHeader) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Extract token from Authorization header
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.put("valid", false);
                response.put("message", "Invalid authorization header");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            String token = authHeader.substring(7);
            boolean isValid = jwtService.validateToken(token);

            if (isValid) {
                String username = jwtService.extractUsername(token);
                response.put("valid", true);
                response.put("username", username);
                response.put("message", "Token is valid");
                return ResponseEntity.ok(response);
            } else {
                response.put("valid", false);
                response.put("message", "Token is invalid or expired");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

        } catch (Exception e) {
            log.warn("Token validation error: {}", e.getMessage());
            response.put("valid", false);
            response.put("message", "Token validation failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user", description = "Get current authenticated user information")
    public ResponseEntity<UserResponseDto> getCurrentUser(
            @AuthenticationPrincipal org.springframework.security.core.userdetails.UserDetails userDetails) {

        User user = (User) userDetails;

        UserResponseDto userResponse = new UserResponseDto();
        userResponse.setId(user.getId());
        userResponse.setUsername(user.getUsername());
        userResponse.setEmail(user.getEmail());
        userResponse.setFirstName(user.getFirstName());
        userResponse.setLastName(user.getLastName());
        userResponse.setFullName(user.getFullName());
        userResponse.setEnabled(user.isEnabled());
        userResponse.setProvider(user.getProvider());
        userResponse.setCreatedAt(user.getCreatedAt());
        userResponse.setLastLogin(user.getLastLogin());
        userResponse.setRoles(user.getRoles().stream()
                .map(role -> role.getName())
                .collect(java.util.stream.Collectors.toSet()));

        return ResponseEntity.ok(userResponse);
    }

    @GetMapping("/login")
    @Operation(summary = "Login page", description = "Display login page with OAuth2 options")
    public ResponseEntity<Map<String, Object>> loginPage() {
        Map<String, Object> loginInfo = new HashMap<>();
        loginInfo.put("message", "Please authenticate using one of the available methods");
        loginInfo.put("localLogin", "/auth/login");
        loginInfo.put("oauth2Providers", Map.of(
                "google", "/oauth2/authorization/google",
                "github", "/oauth2/authorization/github"
        ));
        loginInfo.put("apiDocumentation", "/swagger-ui.html");

        return ResponseEntity.ok(loginInfo);
    }

    // Helper method to extract actor name from request
    private String getActorName(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        return String.format("Anonymous[%s]", clientIp);
    }

    private String getActorName(HttpServletRequest request, String username) {
        return username != null ? username : getActorName(request);
    }
}