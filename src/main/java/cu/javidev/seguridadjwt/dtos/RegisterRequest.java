package cu.javidev.seguridadjwt.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "El nombre de usuario no puede estar vacío")
        @Size(min = 4, max = 20, message = "El nombre de usuario debe tener entre 4 y 20 caracteres")
        String username,

        @NotBlank(message = "El nombre no puede estar vacío")
        @Size(min = 2, max = 30, message = "El nombre debe tener entre 2 y 30 caracteres")
        String firstname,

        @NotBlank(message = "El apellido no puede estar vacío")
        @Size(min = 2, max = 30, message = "El apellido debe tener entre 2 y 30 caracteres")
        String lastname,

        @NotBlank(message = "La contraseña no puede estar vacía")
        @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
        String password,

        @NotBlank(message = "La confirmación de la contraseña no puede estar vacía")
        String password_confirm

) {
    public RegisterRequest{
        if (!password.equals(password_confirm)) throw new RuntimeException("Las contraseñas no coinciden");
    }
}
