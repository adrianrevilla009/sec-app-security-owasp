package lab;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class AppTest {
    @Autowired MockMvc mvc;

    @BeforeEach
    void reset() {
        App.Gadget.TRIGGERED.set(false);
    }

    private static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(o);
        }
        return bos.toByteArray();
    }

    @Test
    void gadgetRunsOnVulnerableEndpoint() throws Exception {
        try {
            mvc.perform(post("/vuln/orders").contentType(MediaType.APPLICATION_OCTET_STREAM).content(serialize(new App.Gadget())));
        } catch (Exception ignored) {
            // the endpoint may fail after deserialization; the side effect is what matters
        }
        assertTrue(App.Gadget.TRIGGERED.get(), "readObject of attacker-chosen class must have executed");
    }

    @Test
    void gadgetBlockedOnFixedEndpoint() throws Exception {
        mvc.perform(post("/fixed/orders").contentType(MediaType.APPLICATION_OCTET_STREAM).content(serialize(new App.Gadget())))
            .andExpect(status().isBadRequest());
        assertFalse(App.Gadget.TRIGGERED.get());
    }

    @Test
    void legitimateOrderStillAcceptedOnFixedEndpoint() throws Exception {
        mvc.perform(post("/fixed/orders").contentType(MediaType.APPLICATION_OCTET_STREAM).content(serialize(new App.Order("book", 2))))
            .andExpect(status().isOk()).andExpect(content().string("Order[item=book, quantity=2]"));
    }
}
