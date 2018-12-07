package sd.dutt.shatyaki.rule;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class RuleEngineTestApplication {

	public static void main(String[] args) {
		SpringApplication.run(RuleEngineTestApplication.class, args);

		int i = 0;
		int d = 4;
		try {
			int answer = d / i;
		} catch (ArithmeticException e) {
			throw new NullPointerException("HI NULL EXCEPTION");

		} catch (NullPointerException e) {
			System.out.println("Not null pointer");
		}

	}

}
