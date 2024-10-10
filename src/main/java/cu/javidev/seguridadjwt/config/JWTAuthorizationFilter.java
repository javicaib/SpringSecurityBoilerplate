package cu.javidev.seguridadjwt.config;

import com.auth0.jwt.interfaces.DecodedJWT;
import cu.javidev.seguridadjwt.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

@RequiredArgsConstructor
public class JWTAuthorizationFilter extends OncePerRequestFilter {
    final JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,@NonNull HttpServletResponse response,@NonNull FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = authorizationHeader.substring(7);

        try {
            DecodedJWT decodedJWT = jwtUtils.validateToken(token);
            String username = jwtUtils.getUsernameFromJWT(decodedJWT);
            String authorities = jwtUtils.getClaimFromJWT(decodedJWT,"authorities").asString();
            Collection<? extends GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

            SecurityContext context = SecurityContextHolder.getContext();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);

            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
