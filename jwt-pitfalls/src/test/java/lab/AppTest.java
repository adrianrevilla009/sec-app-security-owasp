package lab;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AppTest {
    static final String HS256 = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    static final String NONE = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
    static final String ADMIN = "{\"sub\":\"mallory\",\"role\":\"admin\",\"exp\":4102444800}";
    static final String EXPIRED = "{\"sub\":\"alice\",\"exp\":1}";

    @Autowired MockMvc mvc;

    private String bearer(String t) {
        return "Bearer " + t;
    }

    /** Attacker forges an unsigned token: header alg=none, empty signature. */
    private String unsigned() {
        return App.B64.encodeToString(NONE.getBytes()) + "." + App.B64.encodeToString(ADMIN.getBytes()) + ".";
    }

    @Test
    void algNoneForgeryAcceptedOnVulnerableEndpoint() throws Exception {
        mvc.perform(get("/vuln/me").header("Authorization", bearer(unsigned())))
            .andExpect(status().isOk()).andExpect(content().string(Matchers.containsString("admin")));
    }

    @Test
    void algNoneForgeryRejectedOnFixedEndpoint() throws Exception {
        mvc.perform(get("/fixed/me").header("Authorization", bearer(unsigned()))).andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedPayloadRejectedOnFixedEndpoint() throws Exception {
        String[] p = App.sign(HS256, EXPIRED.replace("\"exp\":1", "\"exp\":4102444800")).split("\\.");
        String forged = p[0] + "." + App.B64.encodeToString(ADMIN.getBytes()) + "." + p[2];
        mvc.perform(get("/fixed/me").header("Authorization", bearer(forged))).andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokenOnlyAcceptedByVulnerableEndpoint() throws Exception {
        String token = App.sign(HS256, EXPIRED);
        mvc.perform(get("/vuln/me").header("Authorization", bearer(token))).andExpect(status().isOk());
        mvc.perform(get("/fixed/me").header("Authorization", bearer(token))).andExpect(status().isUnauthorized());
    }

    @Test
    void validTokenAcceptedOnFixedEndpoint() throws Exception {
        mvc.perform(get("/fixed/me").header("Authorization", bearer(App.sign(HS256, ADMIN))))
            .andExpect(status().isOk());
    }
}
