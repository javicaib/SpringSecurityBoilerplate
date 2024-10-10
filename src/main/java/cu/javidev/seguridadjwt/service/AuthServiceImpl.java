package cu.javidev.seguridadjwt.service;

import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import cu.javidev.seguridadjwt.persistence.entities.RoleEntity;
import cu.javidev.seguridadjwt.persistence.entities.RoleEnum;
import cu.javidev.seguridadjwt.persistence.entities.UserEntity;
import cu.javidev.seguridadjwt.persistence.respositories.UserRepository;
import lombok.RequiredArgsConstructor;

import java.util.HashSet;
import java.util.Set;

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
}
