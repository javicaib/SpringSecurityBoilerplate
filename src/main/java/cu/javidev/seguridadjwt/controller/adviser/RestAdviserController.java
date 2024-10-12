package cu.javidev.seguridadjwt.controller.adviser;

import com.auth0.jwt.exceptions.JWTVerificationException;
import cu.javidev.seguridadjwt.dtos.ErrorResponse;
import cu.javidev.seguridadjwt.utils.errors.ErrorCatalog;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
public class RestAdviserController {


    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException ex) {
        ErrorResponse error = new ErrorResponse(
                ErrorCatalog.INVALID_CREDENTIALS.getCode(),
                ErrorCatalog.INVALID_CREDENTIALS.getMessage(),
                List.of(ex.getMessage())
        );
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(JWTVerificationException.class)
    public ResponseEntity<ErrorResponse> handleJWTVerificationException(JWTVerificationException ex) {
        ErrorResponse error = new ErrorResponse(
                ErrorCatalog.INVALID_CREDENTIALS.getCode(),
                ErrorCatalog.INVALID_CREDENTIALS.getMessage(),
                List.of(ex.getMessage())
        );
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException() {
        ErrorResponse error = new ErrorResponse(
                ErrorCatalog.INVALID_CREDENTIALS.getCode(),
                ErrorCatalog.INVALID_CREDENTIALS.getMessage()
        );
        return new ResponseEntity<>(error, HttpStatus.FORBIDDEN);
    }

    // Manejar excepciones generales
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex) {

        ErrorResponse error = new ErrorResponse(
                ErrorCatalog.INTERNAL_SERVER_ERROR.getCode(),
                ErrorCatalog.INTERNAL_SERVER_ERROR.getMessage(),
                List.of(ex.getMessage())
        );
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
