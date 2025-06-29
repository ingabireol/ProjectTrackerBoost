package com.buildmaster.projecttracker.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.boot.actuate.info.Info.Builder;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.PageRequest;

import com.buildmaster.projecttracker.repository.ProjectRepository;
import com.buildmaster.projecttracker.repository.TaskRepository;
import com.buildmaster.projecttracker.repository.DeveloperRepository;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class PerformanceMonitoringConfig {
    
    private final MeterRegistry meterRegistry;
    private final CacheManager cacheManager;
    
    /**
     * Custom Health Indicator
     */
    @Bean
    public HealthIndicator databaseHealthIndicator(ProjectRepository projectRepository,
                                                   TaskRepository taskRepository,
                                                   DeveloperRepository developerRepository) {
        return () -> {
            try {
                // Quick database connectivity check
                long projectCount = projectRepository.count();
                long taskCount = taskRepository.count();
                long developerCount = developerRepository.count();
                
                Map<String, Object> details = new HashMap<>();
                details.put("database", "UP");
                details.put("projectCount", projectCount);
                details.put("taskCount", taskCount);
                details.put("developerCount", developerCount);
                details.put("timestamp", LocalDateTime.now());
                
                return Health.up().withDetails(details).build();
            } catch (Exception e) {
                return Health.down()
                    .withDetail("database", "DOWN")
                    .withDetail("error", e.getMessage())
                    .build();
            }
        };
    }
    
    /**
     * Cache Health Indicator
     */
    @Bean
    public HealthIndicator cacheHealthIndicator() {
        return () -> {
            try {
                Map<String, Object> cacheDetails = new HashMap<>();
                
                cacheManager.getCacheNames().forEach(cacheName -> {
                    var cache = cacheManager.getCache(cacheName);
                    if (cache != null) {
                        cacheDetails.put(cacheName, "AVAILABLE");
                    }
                });
                
                return Health.up()
                    .withDetail("caches", cacheDetails)
                    .withDetail("cacheProvider", cacheManager.getClass().getSimpleName())
                    .build();
            } catch (Exception e) {
                return Health.down()
                    .withDetail("cache", "DOWN")
                    .withDetail("error", e.getMessage())
                    .build();
            }
        };
    }
    
    /**
     * Custom Info Contributor
     */
    @Bean
    public InfoContributor customInfoContributor() {
        return (builder) -> {
            Map<String, Object> appInfo = new HashMap<>();
            appInfo.put("name", "ProjectTracker");
            appInfo.put("version", "1.0.0-OPTIMIZED");
            appInfo.put("description", "Performance Optimized Project Management System");
            appInfo.put("buildTime", LocalDateTime.now());
            
            Map<String, Object> performance = new HashMap<>();
            performance.put("cachingEnabled", true);
            performance.put("cacheProvider", "Caffeine");
            performance.put("optimizedDTOs", true);
            performance.put("profiledWith", "JProfiler");
            
            builder.withDetail("application", appInfo);
            builder.withDetail("performance", performance);
        };
    }
    
    /**
     * Custom Metrics Beans
     */
    @Bean
    public Counter taskProcessedCounter() {
        return Counter.builder("tasks.processed")
                .description("Number of tasks processed")
                .register(meterRegistry);
    }
    
    @Bean
    public Counter projectCreatedCounter() {
        return Counter.builder("projects.created")
                .description("Number of projects created")
                .register(meterRegistry);
    }
    
    @Bean
    public Timer apiResponseTimer() {
        return Timer.builder("api.response.time")
                .description("API response time")
                .register(meterRegistry);
    }
}