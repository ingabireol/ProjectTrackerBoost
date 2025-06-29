package com.buildmaster.projecttracker.service.impl;

import com.buildmaster.projecttracker.dto.project.ProjectDetailResponseDto;
import com.buildmaster.projecttracker.dto.project.ProjectRequestDto;
import com.buildmaster.projecttracker.dto.project.ProjectResponseDto;
import com.buildmaster.projecttracker.dto.project.TaskSummaryDto;
import com.buildmaster.projecttracker.model.*;
import com.buildmaster.projecttracker.repository.ProjectRepository;
import com.buildmaster.projecttracker.service.AuditLogService;
import com.buildmaster.projecttracker.service.ProjectService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class ProjectServiceImpl implements ProjectService {
    
    private final ProjectRepository projectRepository;
    private final AuditLogService auditLogService;
    
    @Override
    public ProjectResponseDto createProject(ProjectRequestDto projectRequestDto, String actorName) {
        log.info("Creating project with name: {}", projectRequestDto.getName());
        
        // Check if project with same name already exists
        if (projectRepository.existsByNameIgnoreCase(projectRequestDto.getName())) {
            throw new IllegalArgumentException("Project with name '" + projectRequestDto.getName() + "' already exists");
        }
        
        Project project = new Project();
        project.setName(projectRequestDto.getName());
        project.setDescription(projectRequestDto.getDescription());
        project.setDeadline(projectRequestDto.getDeadline());
        project.setStatus(projectRequestDto.getStatus() != null ? projectRequestDto.getStatus() : ProjectStatus.PLANNING);
        
        Project savedProject = projectRepository.save(project);
        
        // Log the creation
        Map<String, Object> payload = createProjectPayload(savedProject);
        auditLogService.logAction(AuditAction.CREATE, EntityType.PROJECT, savedProject.getId(), actorName, payload);
        
        log.info("Project created successfully with ID: {}", savedProject.getId());
        return convertToResponseDto(savedProject);
    }
    
    @Override
    @CacheEvict(value = "projects", key = "#projectId")
    @CachePut(value = "projects", key = "#projectId")
    public ProjectResponseDto updateProject(Long projectId, ProjectRequestDto projectRequestDto, String actorName) {
        log.info("Updating project with ID: {}", projectId);
        
        Project project = findProjectById(projectId);
        
        // Store old data for audit
        Map<String, Object> oldData = createProjectPayload(project);
        
        project.setName(projectRequestDto.getName());
        project.setDescription(projectRequestDto.getDescription());
        project.setDeadline(projectRequestDto.getDeadline());
        if (projectRequestDto.getStatus() != null) {
            project.setStatus(projectRequestDto.getStatus());
        }
        
        Project updatedProject = projectRepository.save(project);
        
        // Log the update
        Map<String, Object> payload = new HashMap<>();
        payload.put("oldData", oldData);
        payload.put("newData", createProjectPayload(updatedProject));
        auditLogService.logAction(AuditAction.UPDATE, EntityType.PROJECT, updatedProject.getId(), actorName, payload);
        
        log.info("Project updated successfully with ID: {}", updatedProject.getId());
        return convertToResponseDto(updatedProject);
    }
    
    @Override
    @CacheEvict(value = "projects", key = "#projectId")
    public void deleteProject(Long projectId, String actorName) {
        log.info("Deleting project with ID: {}", projectId);
        
        Project project = findProjectById(projectId);
        
        // Store data for audit before deletion
        Map<String, Object> payload = createProjectPayload(project);
        
        // Delete project (cascade will delete all tasks)
        projectRepository.delete(project);
        
        // Log the deletion
        auditLogService.logAction(AuditAction.DELETE, EntityType.PROJECT, projectId, actorName, payload);
        
        log.info("Project deleted successfully with ID: {}", projectId);
    }
    
    @Override
    @Cacheable(value = "projects", key = "#projectId")
    public ProjectResponseDto getProjectById(Long projectId) {
        log.debug("Fetching project with ID: {}", projectId);
        Project project = findProjectById(projectId);
        return convertToResponseDto(project);
    }
    
    @Override
    @Cacheable(value = "projectDetails", key = "#projectId")
    public ProjectDetailResponseDto getProjectDetails(Long projectId) {
        log.debug("Fetching project details with ID: {}", projectId);
        Project project = findProjectById(projectId);
        return convertToDetailResponseDto(project);
    }
    
    @Override
    public Page<ProjectResponseDto> getAllProjects(Pageable pageable) {
        log.debug("Fetching all projects with pagination");
        Page<Project> projects = projectRepository.findAll(pageable);
        return projects.map(this::convertToResponseDto);
    }
    
    @Override
    public Page<ProjectResponseDto> getProjectsByStatus(ProjectStatus status, Pageable pageable) {
        log.debug("Fetching projects by status: {}", status);
        Page<Project> projects = projectRepository.findByStatus(status, pageable);
        return projects.map(this::convertToResponseDto);
    }
    
    @Override
    public Page<ProjectResponseDto> searchProjectsByName(String name, Pageable pageable) {
        log.debug("Searching projects by name: {}", name);
        Page<Project> projects = projectRepository.findByNameContainingIgnoreCase(name, pageable);
        return projects.map(this::convertToResponseDto);
    }
    
    @Override
    public List<ProjectResponseDto> getProjectsWithoutTasks() {
        log.debug("Fetching projects without tasks");
        List<Project> projects = projectRepository.findProjectsWithoutTasks();
        return projects.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    public List<ProjectResponseDto> getOverdueProjects() {
        log.debug("Fetching overdue projects");
        List<Project> projects = projectRepository.findOverdueProjects(LocalDateTime.now());
        return projects.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    public List<ProjectResponseDto> getProjectsByDeadlineRange(LocalDateTime startDate, LocalDateTime endDate) {
        log.debug("Fetching projects by deadline range: {} to {}", startDate, endDate);
        List<Project> projects = projectRepository.findByDeadlineBetween(startDate, endDate);
        return projects.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    public Map<String, Long> getProjectStatusStatistics() {
        log.debug("Fetching project status statistics");
        List<Object[]> stats = projectRepository.getProjectStatusStatistics();
        Map<String, Long> statistics = new HashMap<>();
        
        for (Object[] stat : stats) {
            String status = (String) stat[0];
            Long count = ((Number) stat[1]).longValue();
            statistics.put(status, count);
        }
        
        return statistics;
    }
    
    @Override
    public boolean existsByName(String name) {
        return projectRepository.existsByNameIgnoreCase(name);
    }
    
    @Override
    public List<ProjectResponseDto> getProjectsByCreationDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        log.debug("Fetching projects by creation date range: {} to {}", startDate, endDate);
        List<Project> projects = projectRepository.findByCreatedAtBetween(startDate, endDate);
        return projects.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    // Helper methods
    private Project findProjectById(Long projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found with ID: " + projectId));
    }
    
    private ProjectResponseDto convertToResponseDto(Project project) {
        ProjectResponseDto dto = new ProjectResponseDto();
        dto.setId(project.getId());
        dto.setName(project.getName());
        dto.setDescription(project.getDescription());
        dto.setDeadline(project.getDeadline());
        dto.setStatus(project.getStatus());
        dto.setTaskCount(project.getTasks() != null ? project.getTasks().size() : 0);
        dto.setCreatedAt(project.getCreatedAt());
        dto.setUpdatedAt(project.getUpdatedAt());
        return dto;
    }
    
    private ProjectDetailResponseDto convertToDetailResponseDto(Project project) {
        ProjectDetailResponseDto dto = new ProjectDetailResponseDto();
        dto.setId(project.getId());
        dto.setName(project.getName());
        dto.setDescription(project.getDescription());
        dto.setDeadline(project.getDeadline());
        dto.setStatus(project.getStatus());
        dto.setCreatedAt(project.getCreatedAt());
        dto.setUpdatedAt(project.getUpdatedAt());
        
        // Convert tasks to summary DTOs
        if (project.getTasks() != null) {
            List<TaskSummaryDto> taskSummaries = project.getTasks().stream()
                    .map(this::convertToTaskSummaryDto)
                    .collect(Collectors.toList());
            dto.setTasks(taskSummaries);
        }
        
        return dto;
    }
    
    private TaskSummaryDto convertToTaskSummaryDto(Task task) {
        TaskSummaryDto dto = new TaskSummaryDto();
        dto.setId(task.getId());
        dto.setTitle(task.getTitle());
        dto.setStatus(task.getStatus().toString());
        dto.setDueDate(task.getDueDate());
        dto.setAssignedDeveloperName(task.getAssignedDeveloper() != null ? 
                task.getAssignedDeveloper().getName() : null);
        return dto;
    }
    
    private Map<String, Object> createProjectPayload(Project project) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("id", project.getId());
        payload.put("name", project.getName());
        payload.put("description", project.getDescription());
        payload.put("deadline", project.getDeadline());
        payload.put("status", project.getStatus());
        payload.put("taskCount", project.getTasks() != null ? project.getTasks().size() : 0);
        return payload;
    }
}