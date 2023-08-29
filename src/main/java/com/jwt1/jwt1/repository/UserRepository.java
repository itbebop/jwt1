package com.jwt1.jwt1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt1.jwt1.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    public User findByUsername(String username);
}
