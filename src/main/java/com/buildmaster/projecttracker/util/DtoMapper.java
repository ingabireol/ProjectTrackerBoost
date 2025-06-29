package com.buildmaster.projecttracker.util;

import com.buildmaster.projecttracker.dto.developer.DeveloperListDTO;
import com.buildmaster.projecttracker.dto.project.ProjectListDTO;
import com.buildmaster.projecttracker.dto.task.TaskSummaryDTO;
import com.buildmaster.projecttracker.model.Developer;
import com.buildmaster.projecttracker.model.Project;
import com.buildmaster.projecttracker.model.Task;
import lombok.experimental.UtilityClass;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@UtilityClass
public class DtoMapper {
    
    /**
     * Convert Project entity to lightweight ProjectListDTO
     */
    public static ProjectListDTO toProjectListDTO(Project project) {
        return new ProjectListDTO(
            project.getId(),
            project.getName(),
            project.getStatus(),
            project.getDeadline(),
            project.getTasks() != null ? project.getTasks().size() : 0
        );
    }
    
    /**
     * Convert Task entity to lightweight TaskSummaryDTO
     */
    public static TaskSummaryDTO toTaskSummaryDTO(Task task) {
        return new TaskSummaryDTO(
            task.getId(),
            task.getTitle(),
            task.getStatus(),
            task.getDueDate(),
            task.getAssignedDeveloper() != null ? task.getAssignedDeveloper().getName() : null,
            task.isOverdue()
        );
    }
    
    /**
     * Convert Developer entity to lightweight DeveloperListDTO
     */
    public static DeveloperListDTO toDeveloperListDTO(Developer developer) {
        return new DeveloperListDTO(
            developer.getId(),
            developer.getName(),
            developer.getEmail(),
            developer.getTaskCount(),
            developer.getSkills() != null ? developer.getSkills().size() : 0
        );
    }
    
    /**
     * Batch conversion methods for collections
     */
    public static List<ProjectListDTO> toProjectListDTOs(List<Project> projects) {
        return projects.stream()
            .map(DtoMapper::toProjectListDTO)
            .collect(Collectors.toList());
    }
    
    public static List<TaskSummaryDTO> toTaskSummaryDTOs(List<Task> tasks) {
        return tasks.stream()
            .map(DtoMapper::toTaskSummaryDTO)
            .collect(Collectors.toList());
    }
    
    public static List<DeveloperListDTO> toDeveloperListDTOs(List<Developer> developers) {
        return developers.stream()
            .map(DtoMapper::toDeveloperListDTO)
            .collect(Collectors.toList());
    }
}