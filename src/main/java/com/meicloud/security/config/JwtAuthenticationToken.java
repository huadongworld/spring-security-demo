package com.meicloud.security.config;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.meicloud.security.dto.JwtUserLoginDTO;
import lombok.Data;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

/**
 * JWT令牌Token
 *
 * @author HuaDong
 * @since 2021/4/24 21:25
 */
@Data
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 3981518947978158945L;

	private JwtUserLoginDTO jwtUserLoginDTO;
	private String credentials;
	private DecodedJWT token;

	public JwtAuthenticationToken(DecodedJWT token) {
		super(Collections.emptyList());
		this.token = token;
	}

	public JwtAuthenticationToken(JwtUserLoginDTO jwtUserLoginDTO, DecodedJWT token, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.jwtUserLoginDTO = jwtUserLoginDTO;
		this.token = token;
	}

	@Override
	public void setDetails(Object details) {
		super.setDetails(details);
		this.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return credentials;
	}

	@Override
	public Object getPrincipal() {
		return jwtUserLoginDTO;
	}

}
