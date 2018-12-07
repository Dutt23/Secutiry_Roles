package sd.dutt.shatyaki.rule.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.xml.bind.DatatypeConverter;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sd.dutt.shatyaki.rule.entity.User;

@Component
public class TokenProvider {

	private String jwtSecret = "thisiskey";

	private int jwtExpirationInMs = 5 * 60 * 60;

	private BCryptPasswordEncoder bCryptPasswordEncoder;

	public String getUsernameFromToken(String token) {

		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		System.out.println("RESOLVERRR" + claims);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecret))
				.parseClaimsJws(token).getBody();
		System.out.println(claims.get("role") + "HEREEEE");
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public String generateToken(Authentication authentication, User user) {

		return Jwts.builder().setIssuer("Shatyaki").setSubject((user.getName())).setIssuedAt(new Date())
				.setIssuedAt(new Date(System.currentTimeMillis())).claim("name", authentication.getName())
				.claim("role", user.getRole()).claim("password", user.getPassword())
				.setExpiration(new Date(System.currentTimeMillis() + jwtExpirationInMs * 1000))
				.signWith(SignatureAlgorithm.HS512, jwtSecret).compact();

	}

	private String getPasswordFromToken(String token) {
		Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecret))
				.parseClaimsJws(token).getBody();

		return claims.get("password", String.class);
	}

	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		final String password = getPasswordFromToken(token);
		bCryptPasswordEncoder = new BCryptPasswordEncoder();
		System.out.println("token " + password + userDetails.getPassword());

		System.out.println(username.equals(userDetails.getUsername()) && !isTokenExpired(token));
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token)
				&& bCryptPasswordEncoder.matches(password, userDetails.getPassword()));
	}

	UsernamePasswordAuthenticationToken getAuthentication(final String token, final Authentication existingAuth,
			final UserDetails userDetails) {

		final JwtParser jwtParser = Jwts.parser().setSigningKey(jwtSecret);

		final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

		final Claims claims = claimsJws.getBody();

		final Collection<? extends GrantedAuthority> authorities = Arrays
				.stream(claims.get("role").toString().split(",")).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		System.out.println("I have reached right before");
		authorities.stream().forEach(e -> System.out.println(e + "HEREEEEE OW"));
		userDetails.getAuthorities().stream().forEach(e -> System.out.println(e + "HEREEEEE OW"));

		return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
	}

}
