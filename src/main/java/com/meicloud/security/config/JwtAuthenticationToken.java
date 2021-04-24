package com.meicloud.security.config;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.meicloud.security.dto.MemberLoginDTO;
import lombok.Data;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * JWT令牌Token
 *
 * @author HuaDong
 * @since 2021/4/24 21:25
 */
@Data
public class JwtAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 3981518947978158945L;

	private MemberLoginDTO memberLoginDTO;
	private String credentials;
	private DecodedJWT token;

	public JwtAuthenticationToken(MemberLoginDTO memberLoginDTO, DecodedJWT token, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.memberLoginDTO = memberLoginDTO;
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
		return memberLoginDTO;
	}

}
