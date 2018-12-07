package sd.dutt.shatyaki.rule.config;

import java.io.IOException;
import java.io.Serializable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.ws.Response;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import sd.dutt.shatyaki.rule.entity.User;

@Component
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

	@Autowired
	private TokenProvider jwtTokenUtil;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException {
		
//		User user = new User();
//		String header = request.getHeader("Authorization");
//		String authToken = header.replace("Bearer ", "");
//		try {
//        String username = jwtTokenUtil.getUsernameFromToken(authToken);
//		}
//		catch(Exception e)
//		{
//			user.setName(jwtTokenUtil.getUsernameFromToken(authToken));
//			
//			
//		}

		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
	}

}
