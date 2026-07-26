package dev.cairn;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/users/{name}")
    @PreAuthorize("hasRole('ADMIN')")
    public String user(@PathVariable String name) {
        // Runtime.getRuntime().exec(name) is documentation, not a sink.
        String example = "new ProcessBuilder(name)";
        return name;
    }
}
