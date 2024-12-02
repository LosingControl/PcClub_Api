package com.example.PcClub.Repositories;

import com.example.PcClub.Entities.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Integer> {

    Optional<User> findByUsername(String username);
    Optional<User> findByUserId(Integer user_id);

}
