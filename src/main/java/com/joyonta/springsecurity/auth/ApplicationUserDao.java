package com.joyonta.springsecurity.auth;

import java.util.Optional;

public interface ApplicationUserDao {

   Optional<ApplicationUser> selectApplicationUserByUsername (String username);

}
