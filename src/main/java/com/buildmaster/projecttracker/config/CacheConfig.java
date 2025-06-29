package com.buildmaster.projecttracker.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Value("${cache.expire-after-write:300}")
    private int expireAfterWriteSeconds;

    @Value("${cache.maximum-size:1000}")
    private int maximumSize;

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();

        // Set cache names
        cacheManager.setCacheNames(List.of(
                "projects",
                "projectDetails",
                "developers",
                "developerDetails",
                "tasks",
                "projectStats",
                "taskStats",
                "developerStats")
        );

        // Configure Caffeine
        cacheManager.setCaffeine(caffeineCacheBuilder());

        return cacheManager;
    }

    private Caffeine<Object, Object> caffeineCacheBuilder() {
        return Caffeine.newBuilder()
                .maximumSize(maximumSize)
                .expireAfterWrite(expireAfterWriteSeconds, TimeUnit.SECONDS)
                .recordStats(); // Enable cache statistics for monitoring
    }
}