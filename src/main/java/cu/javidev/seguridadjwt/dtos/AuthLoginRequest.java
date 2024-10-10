package cu.javidev.seguridadjwt.dtos;

import jakarta.validation.constraints.NotBlank;

public record AuthLoginRequest(
        @NotBlank(message = "El nombre de usuario no puede estar vacío")
        String username,

        @NotBlank(message = "La contraseña no puede estar vacía")
        String password
) {
}
