package cu.javidev.seguridadjwt.utils.errors;

import lombok.Getter;

@Getter
public enum ErrorCatalog {

    VALIDATION_ERROR("4001", "Error de validación de datos"),
    USER_NOT_FOUND("4041", "Usuario no encontrado"),
    INVALID_CREDENTIALS("4011", "Credenciales inválidas"),
    JWT_EXPIRED("4012", "El token JWT ha expirado"),
    UNAUTHORIZED_ACCESS("4031", "Acceso no autorizado"),
    INTERNAL_SERVER_ERROR("5001", "Error interno del servidor"),
    DATABASE_ERROR("5002", "Error de base de datos"),
    RESOURCE_NOT_FOUND("4042", "Recurso no encontrado"),
    CONFLICT("4091", "Conflicto en la solicitud"),
    BAD_REQUEST("4000", "Solicitud incorrecta");

    private final String code;
    private final String message;

    ErrorCatalog(String code, String message) {
        this.code = code;
        this.message = message;
    }
}
