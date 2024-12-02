package com.example.PcClub.DTOs;

import lombok.Data;

@Data
public class RegistrationUserDto {
    private String login;
    private String password;
    private String confirmPassword;
    private String number;
    private String email;
}
