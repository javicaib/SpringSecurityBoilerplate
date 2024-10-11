package cu.javidev.seguridadjwt.config;

import cu.javidev.seguridadjwt.exceptions.CustomAccessDeniedHandler;
import cu.javidev.seguridadjwt.utils.jwt.JwtUtils;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    final JwtUtils jwtUtils;
    final HandlerExceptionResolver handlerExceptionResolver;

    @Bean
    public SecurityFilterChain configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(http -> {
                    // EndPoints publicos
                    http.requestMatchers(HttpMethod.POST, "/auth/**").permitAll();

                    // EndPoints Privados
                    http.requestMatchers(HttpMethod.GET, "/test").hasAuthority("READ");
                    http.requestMatchers(HttpMethod.POST, "/test").hasAuthority("WRITE");


                    http.anyRequest().denyAll();
                })
                .exceptionHandling(exception -> exception.accessDeniedHandler(new CustomAccessDeniedHandler()))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Usar un estado sin sesión
                )

                .addFilterBefore(new JWTAuthorizationFilter(jwtUtils,handlerExceptionResolver), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
