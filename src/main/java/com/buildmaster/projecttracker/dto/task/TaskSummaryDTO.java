package com.buildmaster.projecttracker.dto.task;

import com.buildmaster.projecttracker.model.TaskStatus;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TaskSummaryDTO {
    private Long id;
    private String title;
    private TaskStatus status;
    private LocalDateTime dueDate;
    private String assignedDeveloperName;
    private boolean isOverdue;
}
