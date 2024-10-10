package cu.javidev.seguridadjwt.utils;


import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.Authentication;

import java.util.Map;

public interface IJwtUtils {
    String generateToken(Authentication authentication);
    DecodedJWT validateToken(String token);
    String getUsernameFromJWT(DecodedJWT token);
    Claim getClaimFromJWT(DecodedJWT token, String claimName);
    Map<String, Claim> getClaimsFromJWT(DecodedJWT token);
}
