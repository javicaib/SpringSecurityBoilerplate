package cu.javidev.seguridadjwt.exceptions;

public class PublicKeyLoadException extends RuntimeException {
    public PublicKeyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}