package lab;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
@RestController
public class App {
    /** The only type the API legitimately accepts. */
    public record Order(String item, int quantity) implements Serializable {}

    /** Stand-in for a gadget class already on the classpath: deserializing it runs code. */
    public static class Gadget implements Serializable {
        public static final AtomicBoolean TRIGGERED = new AtomicBoolean();

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            TRIGGERED.set(true);
        }
    }

    /** Allowlist: Order and the JDK types it needs; everything else is rejected before instantiation. */
    static final ObjectInputFilter ALLOW_ORDER = ObjectInputFilter.Config.createFilter("lab.App$Order;java.lang.*;!*");

    /** VULNERABLE: native deserialization of attacker-controlled bytes. */
    @PostMapping("/vuln/orders")
    String vulnerable(@RequestBody byte[] body) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body))) {
            return String.valueOf(in.readObject());
        }
    }

    /** FIXED: same format but behind a class allowlist; rejected payloads give 400. */
    @PostMapping("/fixed/orders")
    String fixed(@RequestBody byte[] body) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body))) {
            in.setObjectInputFilter(ALLOW_ORDER);
            return String.valueOf(in.readObject());
        } catch (InvalidClassException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "class not allowed");
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
