package com.meicloud.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.meicloud.security.config.JwtAuthenticationToken;
import com.meicloud.security.exception.LoginAuthenticationException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * JWT请求令牌过滤器
 *
 * @author HuaDong
 * @since 2021/4/26 21:22
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter{

	private String tokenName;

	/**
	 * 白名单
	 */
	private List<RequestMatcher> permissiveRequestMatchers;

	/**
	 * 匿名登录也可以访问
	 */
	private List<RequestMatcher> anonymityRequestMatchers;

	private AuthenticationManager authenticationManager;

	private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

	public JwtAuthenticationFilter(String tokenName) {
		this.tokenName = tokenName;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(authenticationManager, "AuthenticationManager must be specified");
		Assert.notNull(successHandler, "AuthenticationSuccessHandler must be specified");
		Assert.notNull(failureHandler, "AuthenticationFailureHandler must be specified");
	}

	protected String getJwtToken(HttpServletRequest request) {
		return request.getHeader(tokenName);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (permissiveRequest(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		Authentication authResult = null;
		AuthenticationException failed = null;
		try {
			String token = getJwtToken(request);
			if (StringUtils.isNotBlank(token)) {
				JwtAuthenticationToken authToken = new JwtAuthenticationToken(JWT.decode(token));
				authResult = this.getAuthenticationManager().authenticate(authToken);
			} else {
				failed = LoginAuthenticationException.JWT_IS_EMPTY;
			}
		} catch (JWTDecodeException e) {

			logger.error("JWT format error", e);
			failed = LoginAuthenticationException.JWT_FORMAT_ERROR;

		} catch (InternalAuthenticationServiceException e) {

			logger.error("An internal error occurred while trying to authenticate the user.");
			failed = LoginAuthenticationException.AUTH_ERROR;

		} catch (AuthenticationException e) {

			failed = e;
		}

		if (authResult != null) {
			successfulAuthentication(request, response, filterChain, authResult);
		} else {
			if (!anonymityRequest(request)) {
				unsuccessfulAuthentication(request, response, failed);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}


	protected void unsuccessfulAuthentication(HttpServletRequest request,
											  HttpServletResponse response, AuthenticationException failed)
			throws IOException, ServletException {
		SecurityContextHolder.clearContext();
		failureHandler.onAuthenticationFailure(request, response, failed);
	}

	protected void successfulAuthentication(HttpServletRequest request,
											HttpServletResponse response, FilterChain chain, Authentication authResult)
			throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(authResult);
		successHandler.onAuthenticationSuccess(request, response, authResult);
	}

	protected AuthenticationManager getAuthenticationManager() {
		return authenticationManager;
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	protected boolean requiresAuthentication(HttpServletRequest request,
											 HttpServletResponse response) {
		return StringUtils.isNotBlank(this.getJwtToken(request));
	}

	/**
	 * 白名单
	 *
	 * @param request
	 * @return
	 */
	protected boolean permissiveRequest(HttpServletRequest request) {
		if (permissiveRequestMatchers == null) {
			return false;
		}

		for (RequestMatcher permissiveMatcher : permissiveRequestMatchers) {
			if (permissiveMatcher.matches(request)) {
				return true;
			}
		}
		return false;
	}

	public void setPermissiveUrl(String... urls) {
		if (permissiveRequestMatchers == null) {
			permissiveRequestMatchers = new ArrayList<>();
		}

		for (String url : urls) {
			permissiveRequestMatchers.add(new AntPathRequestMatcher(url));
		}

	}

	/**
	 * 匿名登录可访问的URL
	 *
	 * @param request
	 * @return
	 */
	protected boolean anonymityRequest(HttpServletRequest request) {
		if (anonymityRequestMatchers == null) {
			return false;
		}

		for (RequestMatcher anonymityMatcher : anonymityRequestMatchers) {
			if (anonymityMatcher.matches(request)) {
				return true;
			}
		}
		return false;
	}

	public void setAnonymityRequestMatchers(String... urls) {
		if (anonymityRequestMatchers == null) {
			anonymityRequestMatchers = new ArrayList<>();
		}

		for (String url : urls) {
			anonymityRequestMatchers.add(new AntPathRequestMatcher(url));
		}
	}

	public void setAuthenticationSuccessHandler(
			AuthenticationSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.successHandler = successHandler;
	}

	public void setAuthenticationFailureHandler(
			AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.failureHandler = failureHandler;
	}

	protected AuthenticationSuccessHandler getSuccessHandler() {
		return successHandler;
	}

	protected AuthenticationFailureHandler getFailureHandler() {
		return failureHandler;
	}

}
