package com.buildmaster.projecttracker.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class MetricsService {
    
    private final MeterRegistry meterRegistry;
    private final CacheManager cacheManager;
    private final Counter taskProcessedCounter;
    private final Counter projectCreatedCounter;
    
    public void incrementTaskProcessed() {
        taskProcessedCounter.increment();
    }
    
    public void incrementProjectCreated() {
        projectCreatedCounter.increment();
    }
    
    public Map<String, Object> getCacheStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        cacheManager.getCacheNames().forEach(cacheName -> {
            Cache cache = cacheManager.getCache(cacheName);
            if (cache != null) {
                // For Caffeine cache, we can get more detailed stats
                var nativeCache = cache.getNativeCache();
                if (nativeCache instanceof com.github.benmanes.caffeine.cache.Cache) {
                    var caffeineCache = (com.github.benmanes.caffeine.cache.Cache<?, ?>) nativeCache;
                    var cacheStats = caffeineCache.stats();
                    
                    Map<String, Object> cacheInfo = new HashMap<>();
                    cacheInfo.put("hitCount", cacheStats.hitCount());
                    cacheInfo.put("missCount", cacheStats.missCount());
                    cacheInfo.put("hitRate", cacheStats.hitRate());
                    cacheInfo.put("evictionCount", cacheStats.evictionCount());
                    cacheInfo.put("estimatedSize", caffeineCache.estimatedSize());
                    
                    stats.put(cacheName, cacheInfo);
                }
            }
        });
        
        return stats;
    }
}