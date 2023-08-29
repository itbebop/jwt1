package com.cors.jwt1.dto;

import lombok.Data;

@Data
public class LoginRequestDto {
    private String username;
    private String password;
}