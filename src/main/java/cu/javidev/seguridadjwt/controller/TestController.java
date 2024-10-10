package cu.javidev.seguridadjwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class TestController {

    // Endpoint para manejar solicitudes GET
    @GetMapping
    public ResponseEntity<String> getTest() {
        return ResponseEntity.ok("GET request received");
    }

    // Endpoint para manejar solicitudes POST
    @PostMapping
    public ResponseEntity<String> postTest(@RequestBody String requestBody) {
        return ResponseEntity.ok("POST request received with body: " + requestBody);
    }

    // Endpoint para manejar solicitudes PUT
    @PutMapping("/{id}")
    public ResponseEntity<String> putTest(@PathVariable("id") Long id, @RequestBody String requestBody) {
        return ResponseEntity.ok("PUT request received for ID: " + id + " with body: " + requestBody);
    }

    // Endpoint para manejar solicitudes DELETE
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteTest(@PathVariable("id") Long id) {
        return ResponseEntity.ok("DELETE request received for ID: " + id);
    }
}
