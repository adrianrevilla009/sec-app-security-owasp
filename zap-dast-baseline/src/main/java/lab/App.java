package lab;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Target for the ZAP baseline scan. Headers are on by default; set HARDENED=false to see ZAP warnings. */
@SpringBootApplication
@RestController
public class App {
    private final boolean hardened = !"false".equals(System.getenv("HARDENED"));

    @GetMapping(value = "/orders", produces = "application/json")
    String orders(HttpServletResponse res) {
        if (hardened) {
            res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("Cache-Control", "no-store");
            res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        }
        return "[{\"id\":1,\"item\":\"book\"}]";
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
