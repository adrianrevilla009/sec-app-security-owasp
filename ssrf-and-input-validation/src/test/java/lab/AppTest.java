package lab;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AppTest {
    static HttpServer internal;
    static String secretUrl;

    @Autowired MockMvc mvc;

    @BeforeAll
    static void startInternalService() throws Exception {
        internal = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        internal.createContext("/secret", ex -> {
            byte[] body = "internal-secret".getBytes();
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        internal.start();
        secretUrl = "http://127.0.0.1:" + internal.getAddress().getPort() + "/secret";
    }

    @AfterAll
    static void stop() {
        internal.stop(0);
    }

    @Test
    void ssrfReachesInternalServiceOnVulnerableEndpoint() throws Exception {
        mvc.perform(get("/vuln/fetch").param("url", secretUrl))
            .andExpect(status().isOk()).andExpect(content().string("internal-secret"));
    }

    @Test
    void ssrfIsBlockedOnFixedEndpoint() throws Exception {
        mvc.perform(get("/fixed/fetch").param("url", secretUrl)).andExpect(status().isBadRequest());
        mvc.perform(get("/fixed/fetch").param("url", "https://169.254.169.254/latest/meta-data")).andExpect(status().isBadRequest());
        mvc.perform(get("/fixed/fetch").param("url", "file:///etc/passwd")).andExpect(status().isBadRequest());
    }

    @Test
    void validOrderAccepted() throws Exception {
        mvc.perform(post("/fixed/orders").contentType(MediaType.APPLICATION_JSON).content("{\"item\":\"book\",\"quantity\":2}"))
            .andExpect(status().isOk()).andExpect(content().string("created 2x book"));
    }

    @Test
    void malformedOrdersRejected() throws Exception {
        mvc.perform(post("/fixed/orders").contentType(MediaType.APPLICATION_JSON).content("{\"item\":\"<b>x</b>\",\"quantity\":2}"))
            .andExpect(status().isBadRequest());
        mvc.perform(post("/fixed/orders").contentType(MediaType.APPLICATION_JSON).content("{\"item\":\"book\",\"quantity\":-5}"))
            .andExpect(status().isBadRequest());
    }
}
