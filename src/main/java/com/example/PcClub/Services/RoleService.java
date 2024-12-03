package com.example.PcClub.Services;

import com.example.PcClub.Entities.Role;
import com.example.PcClub.Enums.Roles;
import com.example.PcClub.Repositories.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public Role getUserRole() {
        return roleRepository.findByRole("ROLE_" + Roles.COMMON_USER.getTitle()).get();
    }
}
