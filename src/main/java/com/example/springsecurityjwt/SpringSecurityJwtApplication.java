package com.example.springsecurityjwt;

import com.example.springsecurityjwt.domain.Role;
import com.example.springsecurityjwt.domain.User;
import com.example.springsecurityjwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
        CommandLineRunner run(UserService userService) {
            return args -> {



                userService.saveRole(new Role(null, "ROLE_USER"));
                userService.saveRole(new Role(null, "ROLE_MANAGER"));
                userService.saveRole(new Role(null, "ROLE_ADMIN"));
                userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));


                userService.saveUser(new User(null, "Jasson Caceres", "jasson", "123123",new ArrayList<>()));
                userService.saveUser(new User(null, "Junior Caceres", "junior", "123123",new ArrayList<>()));
                userService.saveUser(new User(null, "Jhon Apaza", "jhon", "123123",new ArrayList<>()));
                userService.saveUser(new User(null, "Jose Gomez", "jose", "123123",new ArrayList<>()));

                userService.addRoleToUser("jasson", "ROLE_USER");
                userService.addRoleToUser("jasson", "ROLE_SUPER_ADMIN");
                userService.addRoleToUser("jasson", "ROLE_ADMIN");
                userService.addRoleToUser("junior", "ROLE_USER");
                userService.addRoleToUser("jose", "ROLE_ADMIN");
                userService.addRoleToUser("jhon", "ROLE_USER");

        };
    }
}
