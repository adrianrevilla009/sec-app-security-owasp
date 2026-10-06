package lab;

import java.util.List;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@SpringBootApplication
@RestController
public class App {

    @GetMapping({"/vuln/orders", "/fixed/orders"})
    String orders() {
        return "orders";
    }

    @PostMapping({"/vuln/transfer", "/fixed/transfer"})
    String transfer() {
        return "transferred";
    }

    /** VULNERABLE: no CSRF token, any origin allowed with credentials, no security headers. */
    @Bean
    @Order(1)
    SecurityFilterChain vulnerable(HttpSecurity http) throws Exception {
        CorsConfiguration open = new CorsConfiguration();
        open.setAllowedOriginPatterns(List.of("*"));
        open.setAllowedMethods(List.of("GET", "POST"));
        open.setAllowCredentials(true);
        return http.securityMatcher("/vuln/**")
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable)
            .cors(c -> c.configurationSource(source(open)))
            .headers(h -> h.disable())
            .build();
    }

    /** FIXED: CSRF token required, single trusted origin, CSP and frame protection. */
    @Bean
    @Order(2)
    SecurityFilterChain fixed(HttpSecurity http) throws Exception {
        CorsConfiguration strict = new CorsConfiguration();
        strict.setAllowedOrigins(List.of("https://shop.example"));
        strict.setAllowedMethods(List.of("GET", "POST"));
        strict.setAllowCredentials(true);
        return http.securityMatcher("/fixed/**")
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults())
            .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .cors(c -> c.configurationSource(source(strict)))
            .headers(h -> h.contentSecurityPolicy(p -> p.policyDirectives("default-src 'self'; frame-ancestors 'none'"))
                .frameOptions(f -> f.deny()))
            .build();
    }

    private static CorsConfigurationSource source(CorsConfiguration cfg) {
        UrlBasedCorsConfigurationSource s = new UrlBasedCorsConfigurationSource();
        s.registerCorsConfiguration("/**", cfg);
        return s;
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
