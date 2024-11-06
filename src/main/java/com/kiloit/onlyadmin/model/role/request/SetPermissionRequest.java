package com.kiloit.onlyadmin.model.role.request;

import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SetPermissionRequest {
    private Long roleId;
    private Set<SetPermissionItemRequest> items;
}
