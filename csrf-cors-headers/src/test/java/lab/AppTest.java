package lab;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AppTest {
    static final String EVIL = "https://evil.example";

    @Autowired MockMvc mvc;

    @Test
    void forgedPostWithoutTokenSucceedsOnVulnerableEndpoint() throws Exception {
        mvc.perform(post("/vuln/transfer").with(user("alice"))).andExpect(status().isOk());
    }

    @Test
    void forgedPostWithoutTokenIsRejectedOnFixedEndpoint() throws Exception {
        mvc.perform(post("/fixed/transfer").with(user("alice"))).andExpect(status().isForbidden());
        mvc.perform(post("/fixed/transfer").with(user("alice")).with(csrf())).andExpect(status().isOk());
    }

    @Test
    void evilOriginIsReflectedWithCredentialsOnVulnerableEndpoint() throws Exception {
        mvc.perform(get("/vuln/orders").with(user("alice")).header("Origin", EVIL))
            .andExpect(header().string("Access-Control-Allow-Origin", EVIL))
            .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @Test
    void evilOriginIsRefusedOnFixedEndpoint() throws Exception {
        mvc.perform(get("/fixed/orders").with(user("alice")).header("Origin", EVIL))
            .andExpect(status().isForbidden())
            .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
        mvc.perform(get("/fixed/orders").with(user("alice")).header("Origin", "https://shop.example"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://shop.example"));
    }

    @Test
    void securityHeadersOnlyOnFixedEndpoint() throws Exception {
        mvc.perform(get("/vuln/orders").with(user("alice"))).andExpect(header().doesNotExist("Content-Security-Policy"));
        mvc.perform(get("/fixed/orders").with(user("alice")))
            .andExpect(header().exists("Content-Security-Policy"))
            .andExpect(header().string("X-Frame-Options", "DENY"));
    }
}
