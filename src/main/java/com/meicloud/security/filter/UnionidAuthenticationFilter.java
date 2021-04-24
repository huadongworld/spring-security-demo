package com.meicloud.security.filter;

import com.meicloud.security.config.UnionidAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录认证过滤器
 *
 * @author HuaDong
 * @since 2021/4/24 20:22
 */
public class UnionidAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public UnionidAuthenticationFilter() {
		super(new AntPathRequestMatcher("/user/members:login", "POST"));
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.getAuthenticationManager(), "AuthenticationManager must be specified");
		Assert.notNull(this.getSuccessHandler(), "AuthenticationSuccessHandler must be specified");
		Assert.notNull(this.getFailureHandler(), "AuthenticationFailureHandler must be specified");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		// TODO

		UnionidAuthenticationToken token = new UnionidAuthenticationToken(
				null, "这是openId", "这是unionId", "这是nickName", "这是gender", "这是avatarUrl");

		return this.getAuthenticationManager().authenticate(token);
	}

}
