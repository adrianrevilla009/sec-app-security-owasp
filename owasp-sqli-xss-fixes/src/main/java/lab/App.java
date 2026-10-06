package lab;

import java.util.List;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@SpringBootApplication
@RestController
public class App {
    private final JdbcTemplate jdbc;

    public App(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        jdbc.execute("create table orders(id int primary key, customer varchar(40), item varchar(40))");
        jdbc.update("insert into orders values (1,'alice','book'),(2,'bob','lamp')");
    }

    /** VULNERABLE: string concatenation lets the caller rewrite the query. */
    @GetMapping("/vuln/orders")
    List<String> vulnerable(@RequestParam String customer) {
        return jdbc.queryForList("select item from orders where customer = '" + customer + "'", String.class);
    }

    /** FIXED: bound parameter, input is data and never SQL. */
    @GetMapping("/fixed/orders")
    List<String> fixed(@RequestParam String customer) {
        return jdbc.queryForList("select item from orders where customer = ?", String.class, customer);
    }

    /** VULNERABLE: reflects raw input as HTML. */
    @GetMapping(value = "/vuln/greet", produces = "text/html")
    String vulnGreet(@RequestParam String name) {
        return "<p>Hello " + name + "</p>";
    }

    /** FIXED: output-encoded for the HTML context. */
    @GetMapping(value = "/fixed/greet", produces = "text/html")
    String fixedGreet(@RequestParam String name) {
        return "<p>Hello " + HtmlUtils.htmlEscape(name) + "</p>";
    }

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
