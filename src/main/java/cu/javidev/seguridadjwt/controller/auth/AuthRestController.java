package cu.javidev.seguridadjwt.controller.auth;

import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthRestController {

    @PostMapping("/api/v1")
    public RegisterResponse register(@RequestBody @Valid RegisterRequest registerRequest) {
        log.info(registerRequest.toString());
        return new RegisterResponse(registerRequest.toString());
    }
}
