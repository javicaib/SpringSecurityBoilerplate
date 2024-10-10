package cu.javidev.seguridadjwt.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;


import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils implements IJwtUtils {

    @Value("classpath:jwtKeys/private_key.pem")
    Resource privateKey;

    @Value("classpath:jwtKeys/public_key.pem")
    Resource publicKey;


    @Override
    public String generateToken(Authentication authentication) throws Exception {

        // Cargar la clave privada
        RSAPrivateKey pk = loadPrivateKey(privateKey);
        RSAPublicKey pub = loadPublicKey(publicKey);

        // Crear un algoritmo usando la clave privada y RS256
        Algorithm algorithm = Algorithm.RSA256(pub, pk);

        // Obtener los authorities del usuario
        String authorities = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Instant now = Instant.now();
        Instant expirationDate = now.plusSeconds(60 * 60 * 3);

        return JWT.create()
                .withSubject(authentication.getName())
                .withIssuer("auth0")
                .withIssuedAt(now)
                .withExpiresAt(expirationDate)
                .withJWTId(UUID.randomUUID().toString())
                .withNotBefore(now)
                .withClaim("authorities", authorities)
                .sign(algorithm);

    }

    @Override
    public DecodedJWT validateToken(String token) throws Exception {
        try {
            RSAPrivateKey pk = loadPrivateKey(privateKey);
            RSAPublicKey pub = loadPublicKey(publicKey);
            Algorithm algorithm = Algorithm.RSA256(pub, pk);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("auth0")
                    .build();
            return verifier.verify(token);
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException(exception.getMessage());
        }

    }

    @Override
    public String getUsernameFromJWT(DecodedJWT token) {
        return token.getSubject();
    }

    @Override
    public Claim getClaimFromJWT(DecodedJWT token, String claimName) {
        return token.getClaim(claimName);
    }

    @Override
    public Map<String, Claim> getClaimsFromJWT(DecodedJWT token) {
        return token.getClaims();
    }


    private RSAPrivateKey loadPrivateKey(Resource resource) throws Exception {

        byte[] keyBytes = getResource(resource);

        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }


    private RSAPublicKey loadPublicKey(Resource resource) throws Exception {
        byte[] keyBytes = getResource(resource);

        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private byte[] getResource(Resource resource) throws Exception {
        return Files.readAllBytes(Paths.get(resource.getURI()));
    }


}

