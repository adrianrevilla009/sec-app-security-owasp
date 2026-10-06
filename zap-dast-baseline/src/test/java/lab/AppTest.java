package lab;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/** Cheap pre-check of the headers ZAP's baseline rules look for, runnable without Docker. */
@SpringBootTest
@AutoConfigureMockMvc
class AppTest {
    @Autowired MockMvc mvc;

    @Test
    void responseCarriesTheHeadersZapBaselineChecks() throws Exception {
        mvc.perform(get("/orders")).andExpect(status().isOk())
            .andExpect(header().exists("Content-Security-Policy"))
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(header().string("Cache-Control", "no-store"));
    }
}
