package cu.javidev.seguridadjwt.controller.auth;

import cu.javidev.seguridadjwt.dtos.AuthLoginRequest;
import cu.javidev.seguridadjwt.dtos.AuthLoginResponse;
import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import cu.javidev.seguridadjwt.service.IAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthRestController {
    final IAuthService authService;
    final PasswordEncoder passwordEncoder;

    @PostMapping("/api/v1/register")
    public RegisterResponse register(@RequestBody @Valid RegisterRequest registerRequest) {

        return authService.register(registerRequest);
    }

    @PostMapping("/api/v1/login")
    public AuthLoginResponse login(@RequestBody @Valid AuthLoginRequest authLoginRequest){
        return authService.login(authLoginRequest);
    }

    @GetMapping("/api/v1/getPassword")
    public String getPassword(){
        return passwordEncoder.encode("123456");
    }
}
