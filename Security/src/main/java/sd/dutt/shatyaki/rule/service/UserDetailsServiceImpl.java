package sd.dutt.shatyaki.rule.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import sd.dutt.shatyaki.rule.entity.User;

@Service(value = "userService")
public class UserDetailsServiceImpl implements UserDetailsService, UserService {
	@Autowired
	private BCryptPasswordEncoder bcryptEncoder;

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = new User();

		user.setEmail("shatyaki_dutt@hotmail.com");
		user.setName("Shatyaki");
		user.setRole("ADMIN");
		user.setPassword(bcryptEncoder.encode("password5"));

		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		authorities.add(new SimpleGrantedAuthority(user.getRole()));

		// First field is name second one is password
		return new org.springframework.security.core.userdetails.User(user.getName(), user.getPassword(), authorities);
	}

}
