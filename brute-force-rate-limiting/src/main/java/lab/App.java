package lab;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@SpringBootApplication
@RestController
public class App {
    static final int MAX_FAILURES = 5;
    static final Duration LOCKOUT = Duration.ofMinutes(15);

    /** Demo credential store; real systems keep salted password hashes. */
    private final Map<String, String> users = Map.of("alice", "correct-horse");
    private final Map<String, Integer> failures = new ConcurrentHashMap<>();
    private final Map<String, Instant> lockedUntil = new ConcurrentHashMap<>();
    private final Clock clock;

    public App(Clock clock) {
        this.clock = clock;
    }

    @Bean
    static Clock clock() {
        return Clock.systemUTC();
    }

    /** VULNERABLE: unlimited guesses. */
    @PostMapping("/vuln/login")
    String vulnerable(@RequestParam String user, @RequestParam String password) {
        return check(user, password);
    }

    /** FIXED: after MAX_FAILURES wrong guesses the account answers 429 until the lockout expires. */
    @PostMapping("/fixed/login")
    String fixed(@RequestParam String user, @RequestParam String password) {
        Instant until = lockedUntil.get(user);
        if (until != null) {
            if (clock.instant().isBefore(until)) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);
            lockedUntil.remove(user);
            failures.remove(user);
        }
        try {
            String ok = check(user, password);
            failures.remove(user);
            return ok;
        } catch (ResponseStatusException e) {
            if (failures.merge(user, 1, Integer::sum) >= MAX_FAILURES) lockedUntil.put(user, clock.instant().plus(LOCKOUT));
            throw e;
        }
    }

    private String check(String user, String password) {
        if (!password.equals(users.get(user))) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        return "welcome " + user;
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
