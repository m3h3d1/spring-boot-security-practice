package com.spring.securityPractice.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import java.util.List;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private long id;
    private String userId;
    private String email;

    @JsonIgnore // Hide 'password' from JSON serialization
    private String password;

    private String token;
}