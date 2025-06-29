package com.buildmaster.projecttracker.dto.developer;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeveloperListDTO {
    private Long id;
    private String name;
    private String email;
    private int taskCount;
    private int skillCount;
}