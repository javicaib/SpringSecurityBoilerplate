package cu.javidev.seguridadjwt.service;

import cu.javidev.seguridadjwt.dtos.AuthLoginRequest;
import cu.javidev.seguridadjwt.dtos.AuthLoginResponse;
import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import cu.javidev.seguridadjwt.persistence.entities.UserEntity;
import cu.javidev.seguridadjwt.persistence.respositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {
    final UserRepository userRepository;

    @Override
    public RegisterResponse register(RegisterRequest registerRequest) {
        UserEntity user = UserEntity.builder()
                .username(registerRequest.username())
                .password(registerRequest.password())
                .roles(null)
                .accountNoLocked(true)
                .accountNoExpired(true)
                .credentialNoExpired(true)
                .isEnabled(true)
                .build();
        userRepository.save(user);
        return new RegisterResponse(String.format("User: %s create", user.getUsername()));
    }

    @Override
    public AuthLoginResponse login(AuthLoginRequest authLoginRequest) {
        Optional<UserEntity> user = userRepository.findByUsername(authLoginRequest.username());

        if (user.isEmpty()) {
            throw new RuntimeException("Invalid username or password");
        }

        if (!user.get().getPassword().equals(authLoginRequest.password())) {
            throw new RuntimeException("Invalid username or password");
        }

        return new AuthLoginResponse(String.format("User: %s login", user.get().getUsername()));
    }
}
