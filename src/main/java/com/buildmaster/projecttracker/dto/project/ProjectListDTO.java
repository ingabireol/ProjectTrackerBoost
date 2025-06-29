package com.buildmaster.projecttracker.dto.project;

import com.buildmaster.projecttracker.model.ProjectStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProjectListDTO {
    private Long id;
    private String name;
    private ProjectStatus status;
    private LocalDateTime deadline;
    private int taskCount;
}