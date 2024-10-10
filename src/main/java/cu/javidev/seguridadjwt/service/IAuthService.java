package cu.javidev.seguridadjwt.service;

import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import org.springframework.stereotype.Service;

@Service
public interface IAuthService {
    RegisterResponse register(RegisterRequest registerRequest);
}
