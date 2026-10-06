package lab;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Minimal HS256 JWT handling written by hand so the pitfalls are visible. */
@SpringBootApplication
@RestController
public class App {
    /** Demo key only; real keys come from a secret store and are at least 256 bits. */
    static final byte[] KEY = "lab-only-hmac-key-0123456789-abcdef".getBytes(StandardCharsets.UTF_8);
    static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    static String sign(String headerJson, String payloadJson) {
        String head = B64.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String body = B64.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return head + "." + body + "." + B64.encodeToString(hmac(head + "." + body));
    }

    static byte[] hmac(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String decode(String part) {
        return new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8);
    }

    /** VULNERABLE: trusts the alg header, so "none" skips the signature check entirely. */
    static String vulnerableVerify(String token) {
        String[] p = token.split("\\.", -1);
        if (p.length != 3) throw new IllegalArgumentException("malformed");
        if (decode(p[0]).contains("\"none\"")) return decode(p[1]);
        if (!p[2].equals(B64.encodeToString(hmac(p[0] + "." + p[1])))) throw new IllegalArgumentException("bad signature");
        return decode(p[1]);
    }

    /** FIXED: algorithm pinned server-side, constant-time compare, expiry enforced. */
    static String fixedVerify(String token, long nowEpochSeconds) {
        String[] p = token.split("\\.", -1);
        if (p.length != 3 || !decode(p[0]).replace(" ", "").contains("\"alg\":\"HS256\"")) throw new IllegalArgumentException("bad header");
        byte[] expected = hmac(p[0] + "." + p[1]);
        if (!MessageDigest.isEqual(expected, Base64.getUrlDecoder().decode(p[2]))) throw new IllegalArgumentException("bad signature");
        String payload = decode(p[1]);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"exp\":(\\d+)").matcher(payload);
        if (!m.find() || Long.parseLong(m.group(1)) < nowEpochSeconds) throw new IllegalArgumentException("expired");
        return payload;
    }

    @GetMapping("/vuln/me")
    String vulnMe(@RequestHeader("Authorization") String auth) {
        try {
            return vulnerableVerify(auth.replace("Bearer ", ""));
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }

    @GetMapping("/fixed/me")
    String fixedMe(@RequestHeader("Authorization") String auth) {
        try {
            return fixedVerify(auth.replace("Bearer ", ""), System.currentTimeMillis() / 1000);
        } catch (RuntimeException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
