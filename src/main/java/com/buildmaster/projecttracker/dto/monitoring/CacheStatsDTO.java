package com.buildmaster.projecttracker.dto.monitoring;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CacheStatsDTO {
    private String cacheName;
    private long hitCount;
    private long missCount;
    private double hitRate;
    private long evictionCount;
    private long size;
}