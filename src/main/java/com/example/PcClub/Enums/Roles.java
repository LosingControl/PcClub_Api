package com.example.PcClub.Enums;

public enum Roles {
    COMMON_USER ("common_user"),
    ADMIN_USER ("admin_user");

    private final String title;

    Roles(String role) {
        title = role;
    }

    public String getTitle() {
        return title;
    }
}
