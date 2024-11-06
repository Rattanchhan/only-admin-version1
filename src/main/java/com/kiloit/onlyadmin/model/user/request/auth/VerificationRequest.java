package com.kiloit.onlyadmin.model.user.request.auth;

import jakarta.validation.constraints.NotBlank;

public record VerificationRequest(
    @NotBlank(message = "Email is required")
    String email,
    @NotBlank(message = "Verified code is required")
    String verifiedCode
) {
    
}
