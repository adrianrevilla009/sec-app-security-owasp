package lab;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AppTest {
    static final String SQLI = "x' OR '1'='1";
    static final String XSS = "<script>alert(1)</script>";

    @Autowired MockMvc mvc;

    @Test
    void sqlInjectionLeaksAllRowsOnVulnerableEndpoint() throws Exception {
        mvc.perform(get("/vuln/orders").param("customer", SQLI))
            .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void sqlInjectionIsInertOnFixedEndpoint() throws Exception {
        mvc.perform(get("/fixed/orders").param("customer", SQLI))
            .andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/fixed/orders").param("customer", "alice"))
            .andExpect(jsonPath("$[0]").value("book"));
    }

    @Test
    void xssIsReflectedOnVulnerableEndpoint() throws Exception {
        mvc.perform(get("/vuln/greet").param("name", XSS))
            .andExpect(content().string(containsString(XSS)));
    }

    @Test
    void xssIsEncodedOnFixedEndpoint() throws Exception {
        mvc.perform(get("/fixed/greet").param("name", XSS))
            .andExpect(content().string(not(containsString("<script>"))))
            .andExpect(content().string(containsString("&lt;script&gt;")));
    }
}
