package com.example.PcClub.Repositories;

import org.springframework.data.repository.CrudRepository;
import com.example.PcClub.Entities.Role;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends CrudRepository<Role, Integer> {
    Optional<Role> findByRole(String name);
}
