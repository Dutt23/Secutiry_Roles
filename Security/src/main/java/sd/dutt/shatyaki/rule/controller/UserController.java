package sd.dutt.shatyaki.rule.controller;

import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sd.dutt.shatyaki.rule.config.TokenProvider;
import sd.dutt.shatyaki.rule.entity.User;

@RestController
@RequestMapping("/test/reg")
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

	@Autowired
	TokenProvider tokenProvider;

	@Autowired
	private AuthenticationManager authenticationManager;

	private String jwt;

	private String jwtSecret = "thisiskey";

	private int jwtExpirationInMs = 24 * 60 * 2;

	@PostMapping("public/login")
	public Object loginUser(@RequestBody User user) {

		Date now = new Date();
		Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

		String token = Jwts.builder().setIssuer("Shatyaki").setSubject((user.getEmail())).setIssuedAt(new Date())
				.claim("name", user.getName()).claim("role", user.getRole()).setExpiration(expiryDate)
				.signWith(SignatureAlgorithm.HS512, jwtSecret).compact();

		Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecret))
				.parseClaimsJws(token).getBody();

		return claims.get("role");
	}

	@PreAuthorize("hasAuthority('ADMIN') or hasAuthority('USER')")
	@RequestMapping(value = "/admin", method = RequestMethod.POST)
	public Object secureRouteTest() {
		return "success";
	}

	@RequestMapping(value = "public/token", method = RequestMethod.POST)
	public Object test(@RequestBody User user) {

		 final Authentication authentication = new
		 UsernamePasswordAuthenticationToken(user.getName(),
		 user.getPassword());

//		 final Authentication authentication = authenticationManager
//				.authenticate(new UsernamePasswordAuthenticationToken(user.getName(), user.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		final String token = tokenProvider.generateToken(authentication, user);

		return token;

	}

}
