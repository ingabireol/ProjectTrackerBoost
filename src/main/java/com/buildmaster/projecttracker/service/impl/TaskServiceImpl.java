package com.buildmaster.projecttracker.service.impl;

import com.buildmaster.projecttracker.dto.task.*;
import com.buildmaster.projecttracker.model.*;
import com.buildmaster.projecttracker.repository.DeveloperRepository;
import com.buildmaster.projecttracker.repository.ProjectRepository;
import com.buildmaster.projecttracker.repository.TaskRepository;
import com.buildmaster.projecttracker.service.AuditLogService;
import com.buildmaster.projecttracker.service.TaskService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class TaskServiceImpl implements TaskService {
    
    private final TaskRepository taskRepository;
    private final ProjectRepository projectRepository;
    private final DeveloperRepository developerRepository;
    private final AuditLogService auditLogService;
    
    @Override
    public TaskResponseDto createTask(TaskRequestDto taskRequestDto, String actorName) {
        log.info("Creating task with title: {}", taskRequestDto.getTitle());
        
        // Validate project exists
        Project project = findProjectById(taskRequestDto.getProjectId());
        
        Task task = new Task();
        task.setTitle(taskRequestDto.getTitle());
        task.setDescription(taskRequestDto.getDescription());
        task.setStatus(taskRequestDto.getStatus() != null ? taskRequestDto.getStatus() : TaskStatus.TODO);
        task.setDueDate(taskRequestDto.getDueDate());
        task.setProject(project);
        
        // Assign developer if provided
        if (taskRequestDto.getAssignedDeveloperId() != null) {
            Developer developer = findDeveloperById(taskRequestDto.getAssignedDeveloperId());
            task.setAssignedDeveloper(developer);
        }
        
        Task savedTask = taskRepository.save(task);
        
        // Log the creation
        Map<String, Object> payload = createTaskPayload(savedTask);
        auditLogService.logAction(AuditAction.CREATE, EntityType.TASK, savedTask.getId(), actorName, payload);
        
        log.info("Task created successfully with ID: {}", savedTask.getId());
        return convertToResponseDto(savedTask);
    }
    
    @Override
    @CacheEvict(value = "tasks", key = "#taskId")
    public TaskResponseDto updateTask(Long taskId, TaskRequestDto taskRequestDto, String actorName) {
        log.info("Updating task with ID: {}", taskId);
        
        Task task = findTaskById(taskId);
        
        // Store old data for audit
        Map<String, Object> oldData = createTaskPayload(task);
        
        // Validate project exists if being changed
        if (!task.getProject().getId().equals(taskRequestDto.getProjectId())) {
            Project newProject = findProjectById(taskRequestDto.getProjectId());
            task.setProject(newProject);
        }
        
        task.setTitle(taskRequestDto.getTitle());
        task.setDescription(taskRequestDto.getDescription());
        if (taskRequestDto.getStatus() != null) {
            task.setStatus(taskRequestDto.getStatus());
        }
        task.setDueDate(taskRequestDto.getDueDate());
        
        // Update assigned developer
        if (taskRequestDto.getAssignedDeveloperId() != null) {
            if (task.getAssignedDeveloper() == null || 
                !task.getAssignedDeveloper().getId().equals(taskRequestDto.getAssignedDeveloperId())) {
                Developer developer = findDeveloperById(taskRequestDto.getAssignedDeveloperId());
                task.setAssignedDeveloper(developer);
            }
        } else {
            task.setAssignedDeveloper(null);
        }
        
        Task updatedTask = taskRepository.save(task);
        
        // Log the update
        Map<String, Object> payload = new HashMap<>();
        payload.put("oldData", oldData);
        payload.put("newData", createTaskPayload(updatedTask));
        auditLogService.logAction(AuditAction.UPDATE, EntityType.TASK, updatedTask.getId(), actorName, payload);
        
        log.info("Task updated successfully with ID: {}", updatedTask.getId());
        return convertToResponseDto(updatedTask);
    }
    
    @Override
    @CacheEvict(value = "tasks", key = "#taskId")
    public void deleteTask(Long taskId, String actorName) {
        log.info("Deleting task with ID: {}", taskId);
        
        Task task = findTaskById(taskId);
        
        // Store data for audit before deletion
        Map<String, Object> payload = createTaskPayload(task);
        
        // Delete task
        taskRepository.delete(task);
        
        // Log the deletion
        auditLogService.logAction(AuditAction.DELETE, EntityType.TASK, taskId, actorName, payload);
        
        log.info("Task deleted successfully with ID: {}", taskId);
    }

    @Override
    @Cacheable(value = "tasks", key = "#taskId")
    public TaskResponseDto getTaskById(Long taskId) {
        log.debug("Fetching task with ID: {} (cache miss)", taskId);
        Task task = findTaskById(taskId);
        return convertToResponseDto(task);
    }


    @Override
    @Cacheable(value = "tasks", key = "'all_' + #pageable.pageNumber + '_' + #pageable.pageSize + '_' + #pageable.sort.toString()")
    public Page<TaskResponseDto> getAllTasks(Pageable pageable) {
        log.debug("Fetching all tasks with pagination (cache miss)");
        Page<Task> tasks = taskRepository.findAll(pageable);
        return tasks.map(this::convertToResponseDto);
    }

    @Override
    @Cacheable(value = "tasks", key = "'project_' + #projectId + '_' + #pageable.pageNumber + '_' + #pageable.pageSize")
    public Page<TaskResponseDto> getTasksByProject(Long projectId, Pageable pageable) {
        log.debug("Fetching tasks by project ID: {} (cache miss)", projectId);
        Page<Task> tasks = taskRepository.findByProjectId(projectId, pageable);
        return tasks.map(this::convertToResponseDto);
    }

    @Override
    @Cacheable(value = "tasks", key = "'developer_' + #developerId + '_' + #pageable.pageNumber + '_' + #pageable.pageSize")
    public Page<TaskResponseDto> getTasksByDeveloper(Long developerId, Pageable pageable) {
        log.debug("Fetching tasks by developer ID: {} (cache miss)", developerId);
        Page<Task> tasks = taskRepository.findByAssignedDeveloperId(developerId, pageable);
        return tasks.map(this::convertToResponseDto);
    }

    @Override
    @Cacheable(value = "tasks", key = "'status_' + #status + '_' + #pageable.pageNumber + '_' + #pageable.pageSize")
    public Page<TaskResponseDto> getTasksByStatus(TaskStatus status, Pageable pageable) {
        log.debug("Fetching tasks by status: {} (cache miss)", status);
        Page<Task> tasks = taskRepository.findByStatus(status, pageable);
        return tasks.map(this::convertToResponseDto);
    }
    
    @Override
    public Page<TaskResponseDto> getUnassignedTasks(Pageable pageable) {
        log.debug("Fetching unassigned tasks");
        Page<Task> tasks = taskRepository.findByAssignedDeveloperIsNull(pageable);
        return tasks.map(this::convertToResponseDto);
    }
    
    @Override
    public Page<TaskResponseDto> searchTasksByTitle(String title, Pageable pageable) {
        log.debug("Searching tasks by title: {}", title);
        Page<Task> tasks = taskRepository.findByTitleContainingIgnoreCase(title, pageable);
        return tasks.map(this::convertToResponseDto);
    }
    
    @Override
    public List<TaskResponseDto> getOverdueTasks() {
        log.debug("Fetching overdue tasks");
        List<Task> tasks = taskRepository.findOverdueTasks(LocalDateTime.now());
        return tasks.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    public List<TaskResponseDto> getTasksDueWithin(int days) {
        log.debug("Fetching tasks due within {} days", days);
        LocalDateTime startDate = LocalDateTime.now();
        LocalDateTime endDate = startDate.plusDays(days);
        List<Task> tasks = taskRepository.findTasksDueWithin(startDate, endDate);
        return tasks.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    public List<TaskResponseDto> getTasksWithoutDueDate() {
        log.debug("Fetching tasks without due date");
        List<Task> tasks = taskRepository.findByDueDateIsNull();
        return tasks.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    @CacheEvict(value = "tasks", key = "#taskId")
    public TaskResponseDto assignTask(Long taskId, Long developerId, String actorName) {
        log.info("Assigning task {} to developer {}", taskId, developerId);
        
        Task task = findTaskById(taskId);
        Developer developer = findDeveloperById(developerId);
        
        // Store old assignment for audit
        Long oldDeveloperId = task.getAssignedDeveloper() != null ? task.getAssignedDeveloper().getId() : null;
        
        task.setAssignedDeveloper(developer);
        Task updatedTask = taskRepository.save(task);
        
        // Log the assignment
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "ASSIGN_TASK");
        payload.put("taskId", taskId);
        payload.put("oldDeveloperId", oldDeveloperId);
        payload.put("newDeveloperId", developerId);
        auditLogService.logAction(AuditAction.UPDATE, EntityType.TASK, taskId, actorName, payload);
        
        return convertToResponseDto(updatedTask);
    }
    
    @Override
    @CacheEvict(value = "tasks", key = "#taskId")
    public TaskResponseDto unassignTask(Long taskId, String actorName) {
        log.info("Unassigning task {}", taskId);
        
        Task task = findTaskById(taskId);
        
        // Store old assignment for audit
        Long oldDeveloperId = task.getAssignedDeveloper() != null ? task.getAssignedDeveloper().getId() : null;
        
        task.setAssignedDeveloper(null);
        Task updatedTask = taskRepository.save(task);
        
        // Log the unassignment
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "UNASSIGN_TASK");
        payload.put("taskId", taskId);
        payload.put("oldDeveloperId", oldDeveloperId);
        auditLogService.logAction(AuditAction.UPDATE, EntityType.TASK, taskId, actorName, payload);
        
        return convertToResponseDto(updatedTask);
    }
    
    @Override
    public int bulkAssignTasks(List<Long> taskIds, Long developerId, String actorName) {
        log.info("Bulk assigning {} tasks to developer {}", taskIds.size(), developerId);
        
        // Validate developer exists
        Developer developer = findDeveloperById(developerId);
        
        int updatedCount = taskRepository.bulkAssignTasks(taskIds, developerId);
        
        // Log the bulk assignment
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "BULK_ASSIGN_TASKS");
        payload.put("taskIds", taskIds);
        payload.put("developerId", developerId);
        payload.put("updatedCount", updatedCount);
        auditLogService.logAction(AuditAction.UPDATE,EntityType.TASK, null, actorName, payload);
        
        return updatedCount;
    }
    
    @Override
    public int bulkUpdateTaskStatusByProject(Long projectId, TaskStatus status, String actorName) {
        log.info("Bulk updating task status to {} for project {}", status, projectId);
        
        // Validate project exists
        findProjectById(projectId);
        
        int updatedCount = taskRepository.updateTaskStatusByProject(projectId, status);
        
        // Log the bulk update
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "BULK_UPDATE_STATUS_BY_PROJECT");
        payload.put("projectId", projectId);
        payload.put("status", status);
        payload.put("updatedCount", updatedCount);
        auditLogService.logAction(AuditAction.UPDATE,EntityType.TASK, null, actorName, payload);
        
        return updatedCount;
    }
    
    @Override
    public List<TaskResponseDto> bulkUpdateTasks(List<Long> taskIds, BulkTaskUpdateDto updateDto, String actorName) {
        log.info("Bulk updating {} tasks", taskIds.size());
        
        List<Task> tasks = taskRepository.findAllById(taskIds);
        List<Task> updatedTasks = new ArrayList<>();
        
        for (Task task : tasks) {
            boolean isUpdated = false;
            
            if (updateDto.getStatus() != null) {
                task.setStatus(updateDto.getStatus());
                isUpdated = true;
            }
            
            if (updateDto.getAssignedDeveloperId() != null) {
                Developer developer = findDeveloperById(updateDto.getAssignedDeveloperId());
                task.setAssignedDeveloper(developer);
                isUpdated = true;
            }
            
            if (updateDto.getDueDate() != null) {
                task.setDueDate(updateDto.getDueDate());
                isUpdated = true;
            }
            
            if (isUpdated) {
                updatedTasks.add(taskRepository.save(task));
            }
        }
        
        // Log the bulk update
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "BULK_UPDATE_TASKS");
        payload.put("taskIds", taskIds);
        payload.put("updateData", updateDto);
        payload.put("updatedCount", updatedTasks.size());
        auditLogService.logAction(AuditAction.UPDATE, EntityType.TASK, null, actorName, payload);
        
        return updatedTasks.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    @Override
    public Page<TaskResponseDto> getTasksByCriteria(Long projectId, Long developerId, 
                                                   TaskStatus status, String title, Pageable pageable) {
        log.debug("Fetching tasks by criteria - project: {}, developer: {}, status: {}, title: {}", 
                 projectId, developerId, status, title);
        Page<Task> tasks = taskRepository.findTasksByCriteria(projectId, developerId, status, title, pageable);
        return tasks.map(this::convertToResponseDto);
    }
    
    @Override
    public Map<String, Long> getTaskStatusStatisticsByProject(Long projectId) {
        log.debug("Fetching task status statistics for project: {}", projectId);
        List<Object[]> stats = taskRepository.getTaskStatusStatisticsByProject(projectId);
        return convertStatisticsToMap(stats);
    }
    
    @Override
    public Map<String, Long> getTaskStatusStatisticsByDeveloper(Long developerId) {
        log.debug("Fetching task status statistics for developer: {}", developerId);
        List<Object[]> stats = taskRepository.getTaskStatusStatisticsByDeveloper(developerId);
        return convertStatisticsToMap(stats);
    }
    
    @Override
    public Map<String, Long> getOverallTaskStatistics() {
        log.debug("Fetching overall task statistics");
        Map<String, Long> statistics = new HashMap<>();
        
        for (TaskStatus status : TaskStatus.values()) {
            long count = taskRepository.countByStatus(status);
            statistics.put(status.toString(), count);
        }
        
        // Additional statistics
        statistics.put("TOTAL", taskRepository.count());
        statistics.put("UNASSIGNED", (long) taskRepository.findByAssignedDeveloperIsNull().size());
        statistics.put("OVERDUE", (long) taskRepository.findOverdueTasks(LocalDateTime.now()).size());
        
        return statistics;
    }
    
    @Override
    public List<TaskResponseDto> getTasksByCreationDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        log.debug("Fetching tasks by creation date range: {} to {}", startDate, endDate);
        List<Task> tasks = taskRepository.findByCreatedAtBetween(startDate, endDate);
        return tasks.stream()
                .map(this::convertToResponseDto)
                .collect(Collectors.toList());
    }
    
    // Helper methods
    private Task findTaskById(Long taskId) {
        return taskRepository.findById(taskId)
                .orElseThrow(() -> new RuntimeException("Task not found with ID: " + taskId));
    }
    
    private Project findProjectById(Long projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new RuntimeException("Project not found with ID: " + projectId));
    }
    
    private Developer findDeveloperById(Long developerId) {
        return developerRepository.findById(developerId)
                .orElseThrow(() -> new RuntimeException("Developer not found with ID: " + developerId));
    }
    
    private TaskResponseDto convertToResponseDto(Task task) {
        TaskResponseDto dto = new TaskResponseDto();
        dto.setId(task.getId());
        dto.setTitle(task.getTitle());
        dto.setDescription(task.getDescription());
        dto.setStatus(task.getStatus());
        dto.setDueDate(task.getDueDate());
        dto.setOverdue(task.isOverdue());
        dto.setProjectName(task.getProject().getName());
        dto.setProjectId(task.getProject().getId());
        dto.setAssignedDeveloperName(task.getAssignedDeveloper() != null ? 
                task.getAssignedDeveloper().getName() : null);
        dto.setAssignedDeveloperId(task.getAssignedDeveloper() != null ? 
                task.getAssignedDeveloper().getId() : null);
        dto.setCreatedAt(task.getCreatedAt());
        dto.setUpdatedAt(task.getUpdatedAt());
        return dto;
    }
    
    private Map<String, Object> createTaskPayload(Task task) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("id", task.getId());
        payload.put("title", task.getTitle());
        payload.put("description", task.getDescription());
        payload.put("status", task.getStatus());
        payload.put("dueDate", task.getDueDate());
        payload.put("projectId", task.getProject().getId());
        payload.put("projectName", task.getProject().getName());
        payload.put("assignedDeveloperId", task.getAssignedDeveloper() != null ? 
                task.getAssignedDeveloper().getId() : null);
        payload.put("assignedDeveloperName", task.getAssignedDeveloper() != null ? 
                task.getAssignedDeveloper().getName() : null);
        return payload;
    }
    
    private Map<String, Long> convertStatisticsToMap(List<Object[]> stats) {
        Map<String, Long> statistics = new HashMap<>();
        for (Object[] stat : stats) {
            String status = stat[0].toString();
            Long count = ((Number) stat[1]).longValue();
            statistics.put(status, count);
        }
        return statistics;
    }
}