package cu.javidev.seguridadjwt.service;

import cu.javidev.seguridadjwt.dtos.AuthLoginRequest;
import cu.javidev.seguridadjwt.dtos.AuthLoginResponse;
import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;

public interface IAuthService {
    RegisterResponse register(RegisterRequest registerRequest);
    AuthLoginResponse login(AuthLoginRequest authLoginRequest);
}
