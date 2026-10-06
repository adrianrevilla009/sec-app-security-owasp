package lab;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
@RestController
public class App {
    /** Hosts the service is allowed to call on behalf of users. */
    static final Set<String> ALLOWED_HOSTS = Set.of("images.example.com", "cdn.example.com");

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    /** VULNERABLE: fetches whatever URL the caller supplies, including internal services. */
    @GetMapping("/vuln/fetch")
    String vulnerableFetch(@RequestParam String url) throws Exception {
        return get(URI.create(url));
    }

    /** FIXED: https only, host allowlist, and no resolution to loopback/private/link-local addresses. */
    @GetMapping("/fixed/fetch")
    String fixedFetch(@RequestParam String url) throws Exception {
        URI uri = validate(url);
        return get(uri);
    }

    static URI validate(String url) {
        try {
            URI uri = URI.create(url);
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || !ALLOWED_HOSTS.contains(uri.getHost())) {
                throw new IllegalArgumentException("host not allowed");
            }
            for (InetAddress a : InetAddress.getAllByName(uri.getHost())) {
                if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress()) {
                    throw new IllegalArgumentException("internal address");
                }
            }
            return uri;
        } catch (IllegalArgumentException | java.net.UnknownHostException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "url rejected");
        }
    }

    private String get(URI uri) throws Exception {
        return http.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofString()).body();
    }

    record NewOrder(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9 ]{1,40}") String item,
        @Min(1) @Max(100) int quantity) {}

    /** Input validation: reject malformed orders at the boundary (400 via bean validation). */
    @PostMapping("/fixed/orders")
    String create(@Valid @RequestBody NewOrder order) {
        return "created " + order.quantity() + "x " + order.item();
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
