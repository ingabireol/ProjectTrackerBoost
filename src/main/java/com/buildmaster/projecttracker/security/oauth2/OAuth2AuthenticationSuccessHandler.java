package com.buildmaster.projecttracker.security.oauth2;

import com.buildmaster.projecttracker.model.user.User;
import com.buildmaster.projecttracker.security.service.JwtService;
import com.buildmaster.projecttracker.security.service.CustomOAuth2User;
import com.buildmaster.projecttracker.security.service.AuthService;
import com.buildmaster.projecttracker.model.user.AuthProvider;
import com.buildmaster.projecttracker.security.util.CookieUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.buildmaster.projecttracker.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final AuthService authService;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final ObjectMapper objectMapper;

    @Value("${app.oauth2.authorized-redirect-uris:http://localhost:3000/oauth2/redirect}")
    private String[] authorizedRedirectUris;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);

        // Check if it's an API request (for direct JSON response)
        if (isApiRequest(request)) {
            handleApiResponse(response, authentication);
        } else {
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        }
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {

        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            log.error("Unauthorized Redirect URI: {}", redirectUri.get());
            throw new RuntimeException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        // UPDATED: Better default redirect URL
        String targetUrl = redirectUri.orElse("/oauth2/success");

        // FIXED: Handle both OidcUser and OAuth2User
        User user = extractUserFromAuthentication(authentication);

        // Generate JWT token
        String token = jwtService.generateToken(user);

        // Add token to redirect URL
        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", token)
                .queryParam("type", "oauth2")
                .build().toUriString();
    }

    private void handleApiResponse(HttpServletResponse response, Authentication authentication) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // FIXED: Handle both OidcUser and OAuth2User
        User user = extractUserFromAuthentication(authentication);

        // Generate JWT token
        String token = jwtService.generateToken(user);

        // Create response payload
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", true);
        responseBody.put("message", "OAuth2 authentication successful");
        responseBody.put("accessToken", token);
        responseBody.put("tokenType", "Bearer");
        responseBody.put("expiresIn", jwtService.getExpirationTime());

        // User information
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("id", user.getId());
        userInfo.put("username", user.getUsername());
        userInfo.put("email", user.getEmail());
        userInfo.put("fullName", user.getFullName());
        userInfo.put("provider", user.getProvider());
        userInfo.put("roles", user.getRoles().stream()
                .map(role -> role.getName())
                .toList());

        responseBody.put("user", userInfo);

        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
        response.getWriter().flush();
    }

    /**
     * FIXED: Extract User from either OidcUser or OAuth2User
     */
    private User extractUserFromAuthentication(Authentication authentication) {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // Handle OidcUser (when using openid scope)
        if (oAuth2User instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) oAuth2User;
            log.info("Processing OidcUser: {}", oidcUser.getEmail());

            // Extract user info from OIDC user
            String email = oidcUser.getEmail();
            String name = oidcUser.getFullName();
            String providerId = oidcUser.getSubject(); // OIDC subject

            // Get or create user through AuthService
            return authService.getOrCreateOAuth2User(email, name, providerId, AuthProvider.GOOGLE);
        }
        // Handle regular OAuth2User (from your custom service)
        else if (oAuth2User instanceof CustomOAuth2User) {
            CustomOAuth2User customUser = (CustomOAuth2User) oAuth2User;
            log.info("Processing CustomOAuth2User: {}", customUser.getUser().getUsername());
            return customUser.getUser();
        }
        // Handle default OAuth2User
        else {
            log.info("Processing default OAuth2User: {}", oAuth2User.getName());

            // Extract user info from OAuth2User attributes
            Map<String, Object> attributes = oAuth2User.getAttributes();
            String email = (String) attributes.get("email");
            String name = (String) attributes.get("name");
            String providerId = (String) attributes.get("sub");

            // Get or create user through AuthService
            return authService.getOrCreateOAuth2User(email, name, providerId, AuthProvider.GOOGLE);
        }
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        for (String authorizedRedirectUri : authorizedRedirectUris) {
            URI authorizedURI = URI.create(authorizedRedirectUri);

            if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                    && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                return true;
            }
        }
        return false;
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        return acceptHeader != null && acceptHeader.contains("application/json");
    }
}