package com.buildmaster.projecttracker.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenAPIConfig {

    @Value("${app.version:1.0.0}")
    private String appVersion;

    @Value("${app.description:ProjectTracker API for managing projects, tasks, and developers}")
    private String appDescription;

    @Bean
    public OpenAPI projectTrackerOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("ProjectTracker API")
                        .description(appDescription)
                        .version(appVersion)
                        .contact(new Contact()
                                .name("ProjectTracker Team")
                                .email("support@projecttracker.com")
                                .url("https://projecttracker.com"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .externalDocs(new ExternalDocumentation()
                        .description("ProjectTracker Documentation")
                        .url("https://docs.projecttracker.com"))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8080")
                                .description("Development Server"),
                        new Server()
                                .url("https://api.projecttracker.com")
                                .description("Production Server"),
                        new Server()
                                .url("https://staging-api.projecttracker.com")
                                .description("Staging Server")
                ))
                .addSecurityItem(new SecurityRequirement()
                        .addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", createBearerAuthScheme())
                        .addSecuritySchemes("basicAuth", createBasicAuthScheme())
                        .addSecuritySchemes("oauth2", createOAuth2Scheme()))
                .addTagsItem(new Tag()
                        .name("Authentication")
                        .description("Authentication and authorization endpoints"))
                .addTagsItem(new Tag()
                        .name("User Management")
                        .description("User profile and management operations"))
                .addTagsItem(new Tag()
                        .name("Admin Operations")
                        .description("Administrative operations (Admin role required)"))
                .addTagsItem(new Tag()
                        .name("Projects")
                        .description("Project management operations"))
                .addTagsItem(new Tag()
                        .name("Tasks")
                        .description("Task management operations"))
                .addTagsItem(new Tag()
                        .name("Developers")
                        .description("Developer management operations"))
                .addTagsItem(new Tag()
                        .name("Audit Logs")
                        .description("System audit and logging operations"));
    }

    /**
     * Create JWT Bearer Authentication scheme
     */
    private SecurityScheme createBearerAuthScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("JWT Bearer Token Authentication. " +
                        "Obtain a token by calling the /auth/login endpoint. " +
                        "Format: Bearer {your-jwt-token}");
    }

    /**
     * Create Basic Authentication scheme (for initial setup or emergency access)
     */
    private SecurityScheme createBasicAuthScheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("basic")
                .description("Basic HTTP Authentication. " +
                        "Use for initial setup or emergency access only.");
    }

    /**
     * Create OAuth2 Authentication scheme (for future OAuth2 integration)
     */
    private SecurityScheme createOAuth2Scheme() {
        return new SecurityScheme()
                .type(SecurityScheme.Type.OAUTH2)
                .description("OAuth2 Authentication for third-party integrations")
                .flows(new io.swagger.v3.oas.models.security.OAuthFlows()
                        .authorizationCode(new io.swagger.v3.oas.models.security.OAuthFlow()
                                .authorizationUrl("https://auth.projecttracker.com/oauth/authorize")
                                .tokenUrl("https://auth.projecttracker.com/oauth/token")
                                .refreshUrl("https://auth.projecttracker.com/oauth/refresh")
                                .scopes(new io.swagger.v3.oas.models.security.Scopes()
                                        .addString("read", "Read access to resources")
                                        .addString("write", "Write access to resources")
                                        .addString("admin", "Administrative access"))));
    }

}