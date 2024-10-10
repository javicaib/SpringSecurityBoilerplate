package cu.javidev.seguridadjwt.service;

import cu.javidev.seguridadjwt.dtos.AuthLoginRequest;
import cu.javidev.seguridadjwt.dtos.AuthLoginResponse;
import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import cu.javidev.seguridadjwt.persistence.entities.RoleEntity;
import cu.javidev.seguridadjwt.persistence.entities.RoleEnum;
import cu.javidev.seguridadjwt.persistence.entities.UserEntity;
import cu.javidev.seguridadjwt.persistence.respositories.RoleRepository;
import cu.javidev.seguridadjwt.persistence.respositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {
    final UserRepository userRepository;
    final RoleRepository roleRepository;

    @Override
    public RegisterResponse register(RegisterRequest registerRequest) {
        RoleEntity guestRole = roleRepository.findByRoleEnum(RoleEnum.GUEST).orElse(null);

        UserEntity user = UserEntity.builder()
                .username(registerRequest.username())
                .password(registerRequest.password_confirm())
                .roles(Collections.singleton(guestRole))
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
