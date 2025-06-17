package com.buildmaster.projecttracker.security.config;

import com.buildmaster.projecttracker.security.filter.JwtAuthenticationFilter;
import com.buildmaster.projecttracker.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.buildmaster.projecttracker.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.buildmaster.projecttracker.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.buildmaster.projecttracker.security.service.OAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2UserService oAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for stateless APIs
                .csrf(AbstractHttpConfigurer::disable)

                // Configure CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Configure session management (stateless)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers("/", "/auth/**", "/login/**", "/error").permitAll()

                        // OAuth2 endpoints - USE SPRING'S DEFAULT PATHS
                        .requestMatchers("/oauth2/**").permitAll()
                        .requestMatchers("/login/oauth2/**").permitAll()

                        // Swagger and API docs
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/api-docs/**").permitAll()
                        .requestMatchers("/swagger-resources/**").permitAll()
                        .requestMatchers("/webjars/**").permitAll()

                        // Health and info endpoints
                        .requestMatchers("/api/health", "/api/info").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                        // OAuth2 test endpoints
                        .requestMatchers("/oauth2-test/**").permitAll()

                        // Admin endpoints - ADMIN only
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // User management endpoints
                        .requestMatchers(HttpMethod.GET, "/api/users/me").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/users/me").authenticated()
                        .requestMatchers(HttpMethod.GET, "/api/users/profile/access-check/**").authenticated()
                        .requestMatchers("/api/users/**").hasAnyRole("ADMIN", "MANAGER")

                        // Project endpoints
                        .requestMatchers(HttpMethod.GET, "/api/projects/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/projects").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers(HttpMethod.PUT, "/api/projects/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers(HttpMethod.DELETE, "/api/projects/**").hasRole("ADMIN")

                        // Task endpoints
                        .requestMatchers(HttpMethod.GET, "/api/tasks/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/tasks").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers(HttpMethod.PUT, "/api/tasks/**").hasAnyRole("ADMIN", "MANAGER", "DEVELOPER")
                        .requestMatchers(HttpMethod.DELETE, "/api/tasks/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/api/tasks/bulk-*").hasAnyRole("ADMIN", "MANAGER")

                        .requestMatchers("/api/tasks/*/assign/*").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("/api/tasks/*/unassign").hasAnyRole("ADMIN", "MANAGER")

                        // Developer endpoints
                        .requestMatchers(HttpMethod.GET, "/api/developers/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/developers").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers(HttpMethod.PUT, "/api/developers/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers(HttpMethod.DELETE, "/api/developers/**").hasRole("ADMIN")

                        // Audit log endpoints - ADMIN only
                        .requestMatchers("/api/audit-logs/**").hasRole("ADMIN")

                        // All other requests require authentication
                        .anyRequest().authenticated()
                )

                // Configure OAuth2 Login - USE SPRING'S DEFAULTS
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/auth/login")
                        // REMOVE CUSTOM AUTHORIZATION ENDPOINT - Use Spring's default
//                         .authorizationEndpoint(authorization -> authorization.baseUri("/oauth2/authorize"))

                        // REMOVE CUSTOM REDIRECTION ENDPOINT - Use Spring's default
                        // .redirectionEndpoint(redirection -> redirection.baseUri("/oauth2/callback/*"))


//                        .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
                        .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                )

                // Configure authentication provider
                .authenticationProvider(authenticationProvider)

                // Add JWT filter before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow specific origins (configure for production)
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Allow specific HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        // Allow specific headers
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // Allow credentials
        configuration.setAllowCredentials(true);

        // Expose Authorization header and custom headers
        configuration.setExposedHeaders(Arrays.asList("Authorization", "X-Total-Count", "X-Page-Number", "X-Page-Size"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}