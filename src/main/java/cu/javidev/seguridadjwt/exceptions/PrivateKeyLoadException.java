package cu.javidev.seguridadjwt.exceptions;

public class PrivateKeyLoadException extends RuntimeException {
    public PrivateKeyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}