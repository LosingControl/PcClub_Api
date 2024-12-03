package com.example.PcClub.DTOs;

import lombok.Data;

@Data
public class JwtRequest {
    private String login;
    private String password;
}
