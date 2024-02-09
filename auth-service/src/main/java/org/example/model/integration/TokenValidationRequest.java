package org.example.model.integration;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class TokenValidationRequest {

    private String clientName;
    private List<String> permissions;
}
