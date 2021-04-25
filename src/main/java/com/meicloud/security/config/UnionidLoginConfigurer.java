package com.meicloud.security.config;

import com.meicloud.security.filter.UnionidAuthenticationFilter;
import com.meicloud.security.handler.HttpStatusLoginFailureHandler;
import com.meicloud.security.handler.UnionidLoginSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;

/**
 * 登录过滤器配置
 *
 * @author HuaDong
 * @since 2021/4/24 21:10
 */
public class UnionidLoginConfigurer<T extends UnionidLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B>  {

	private SecurityConfig securityConfig;

	public UnionidLoginConfigurer(SecurityConfig securityConfig) {
		this.securityConfig = securityConfig;
	}

	@Override
	public void configure(B http) throws Exception {

		UnionidAuthenticationFilter authFilter = new UnionidAuthenticationFilter();

		authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		authFilter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());

		// 登录成功处理器
		authFilter.setAuthenticationSuccessHandler(new UnionidLoginSuccessHandler(securityConfig));
		// 登录失败处理器
		authFilter.setAuthenticationFailureHandler(new HttpStatusLoginFailureHandler());

		// 拦截器位置
		UnionidAuthenticationFilter filter = postProcess(authFilter);
		http.addFilterAfter(filter, LogoutFilter.class);
	}

}
