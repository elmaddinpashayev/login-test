package com.company.springsecurity.repository;




import com.company.springsecurity.model.ERole;
import com.company.springsecurity.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface RoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(ERole name);
}
