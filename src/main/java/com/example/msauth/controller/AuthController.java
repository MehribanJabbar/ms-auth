package com.example.msauth.controller;

import com.example.msauth.dto.SignInDto;
import com.example.msauth.dto.TokenDto;
import com.example.msauth.service.AuthService;
import com.example.msauth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequiredArgsConstructor
@RequestMapping("v1/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/sign-in")
    @ResponseStatus(OK)
    public TokenDto signIn(@RequestBody @Valid SignInDto dto){
        return authService.signIn(dto);
    }
}
