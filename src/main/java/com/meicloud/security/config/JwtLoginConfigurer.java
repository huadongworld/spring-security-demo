package com.meicloud.security.config;

import com.meicloud.security.filter.JwtAuthenticationFilter;
import com.meicloud.security.handler.HttpStatusLoginFailureHandler;
import com.meicloud.security.handler.JwtRefreshSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * JWT认证过滤器配置
 *
 * @author HuaDong
 * @since 2021/4/26 21:39
 */
public class JwtLoginConfigurer<T extends JwtLoginConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B> {

	private SecurityConfig securityConfig;

	public JwtLoginConfigurer(SecurityConfig securityConfig) {
		this.securityConfig = securityConfig;
	}

	@Override
	public void configure(B http) throws Exception {

		JwtAuthenticationFilter authFilter = new JwtAuthenticationFilter(securityConfig.getTokenName());
		authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

		// 配置白名单
		authFilter.setPermissiveUrl(securityConfig.getPermitUrls());
		// 配置匿名用户可访问的接口
		authFilter.setAnonymityRequestMatchers(securityConfig.getAnonymousUrls());

		// 成功处理器
		authFilter.setAuthenticationSuccessHandler(new JwtRefreshSuccessHandler(securityConfig));
		// 失败处理器
		authFilter.setAuthenticationFailureHandler(new HttpStatusLoginFailureHandler());

		JwtAuthenticationFilter filter = postProcess(authFilter);
		http.addFilterAfter(filter, AnonymousAuthenticationFilter.class);
	}

}
