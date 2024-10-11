package cu.javidev.seguridadjwt.service;

import cu.javidev.seguridadjwt.dtos.AuthLoginRequest;
import cu.javidev.seguridadjwt.dtos.AuthLoginResponse;
import cu.javidev.seguridadjwt.dtos.RegisterRequest;
import cu.javidev.seguridadjwt.dtos.RegisterResponse;
import cu.javidev.seguridadjwt.persistence.entities.PermissionEntity;
import cu.javidev.seguridadjwt.persistence.entities.RoleEntity;
import cu.javidev.seguridadjwt.persistence.entities.RoleEnum;
import cu.javidev.seguridadjwt.persistence.entities.UserEntity;
import cu.javidev.seguridadjwt.persistence.respositories.RoleRepository;
import cu.javidev.seguridadjwt.persistence.respositories.UserRepository;
import cu.javidev.seguridadjwt.utils.jwt.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService, UserDetailsService {
    final UserRepository userRepository;
    final RoleRepository roleRepository;
    final PasswordEncoder passwordEncoder;
    final JwtUtils jwtUtils;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));

        // Inicializar la lista de autoridades
        List<GrantedAuthority> authorityList = new ArrayList<>();

        // Obtener los roles del usuario
        Set<RoleEntity> roles = user.getRoles();

        // Agregar roles a la lista de autoridades
        for (RoleEntity role : roles) {
            // Crear el nombre del rol

            String roleName = "ROLE_" + role.getRoleEnum().name();

            SimpleGrantedAuthority roleAuthority = new SimpleGrantedAuthority(roleName);

            // Agregar la autoridad del rol a la lista
            authorityList.add(roleAuthority);
        }

        // Agregar permisos a la lista de autoridades
        for (RoleEntity role : roles) {
            Set<PermissionEntity> permissions = role.getPermissionList(); // Obtener la lista de permisos

            for (PermissionEntity permission : permissions) {
                SimpleGrantedAuthority permissionAuthority = new SimpleGrantedAuthority(permission.getName());
                authorityList.add(permissionAuthority); // Agregar la autoridad del permiso a la lista
            }
        }

        return new User(
                user.getUsername(),
                user.getPassword(),
                user.isEnabled(),
                user.isAccountNoExpired(),
                user.isCredentialNoExpired(),
                user.isAccountNoLocked(),
                authorityList);

    }

    @Override
    public RegisterResponse register(RegisterRequest registerRequest) {
        RoleEntity guestRole = roleRepository.findByRoleEnum(RoleEnum.GUEST).orElse(null);

        UserEntity user = UserEntity.builder()
                .username(registerRequest.username())
                .password(passwordEncoder.encode(registerRequest.password()))
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
    public AuthLoginResponse login(AuthLoginRequest authLoginRequest){

        String username = authLoginRequest.username();
        String password = authLoginRequest.password();

        Authentication authentication = this.authenticate(username, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtils.generateToken(authentication);

        return new AuthLoginResponse(accessToken);
    }

    public Authentication authenticate(String username, String password) {
        UserDetails user = this.loadUserByUsername(username);
        if (user == null) {
            throw new BadCredentialsException("Invalid username or password");
        }
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return new UsernamePasswordAuthenticationToken(username, user.getPassword(), user.getAuthorities());
    }


}
