package com.example.msauth.client;

import com.example.msauth.model.response.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "ms-auth-user", url = "http://localhost:8082")
public interface UserClient {

    @GetMapping("/v1/users/username")
    UserResponse getUserByUsername(@RequestParam String username);

}
