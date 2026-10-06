package lab;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
@Import(AppTest.MutableClock.class)
class AppTest {
    static final class Ticking extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(java.time.ZoneId z) { return this; }
        public Instant instant() { return now; }
    }

    @TestConfiguration
    static class MutableClock {
        static final Ticking CLOCK = new Ticking();
        @Bean @Primary Clock testClock() { return CLOCK; }
    }

    @Autowired MockMvc mvc;

    private void guess(String path, String user, String pw, int expected) throws Exception {
        mvc.perform(post(path).param("user", user).param("password", pw)).andExpect(status().is(expected));
    }

    @Test
    void unlimitedGuessingSucceedsOnVulnerableEndpoint() throws Exception {
        for (int i = 0; i < 50; i++) guess("/vuln/login", "alice", "guess" + i, 401);
        guess("/vuln/login", "alice", "correct-horse", 200);
    }

    @Test
    void accountLocksAfterFiveFailuresOnFixedEndpoint() throws Exception {
        for (int i = 0; i < App.MAX_FAILURES; i++) guess("/fixed/login", "alice", "guess" + i, 401);
        // even the right password is refused while locked, so guessing cannot continue
        guess("/fixed/login", "alice", "correct-horse", 429);
        // lockout expires with time
        MutableClock.CLOCK.now = MutableClock.CLOCK.now.plus(App.LOCKOUT).plusSeconds(1);
        guess("/fixed/login", "alice", "correct-horse", 200);
    }
}
