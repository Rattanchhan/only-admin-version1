package com.kiloit.onlyadmin.model.user.respone.auth;

import lombok.Builder;
import lombok.Data;

@Builder
public record CustomUserDetailResponse (
    Long id,
    String username,
    String email,
    String avatar,
    String phone,
    String address,
    String roleName,
    Long roleId
){
}