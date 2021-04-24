package com.meicloud.security.config;

import com.meicloud.security.provider.UnionidAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

/**
 * 核心 WebSecurity 配置器
 * 
 * @author HuaDong
 * @since 2021/4/24 20:10
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private SecurityConfig securityConfig;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers(securityConfig.getPermitUrls()).permitAll()
				.anyRequest().authenticated()
				.and()
				.csrf().disable()
				.sessionManagement().disable()
				.cors()
				.and()
				.headers().addHeaderWriter(
				new StaticHeadersWriter(Collections.singletonList(
						new Header("Access-control-Allow-Origin", "*"))))
				.and()
				// 会员unionid登录配置
				.apply(new UnionidLoginConfigurer<>())
				.and()
				.logout()
				.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
				.and()
				.sessionManagement().disable();

	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(unionidAuthenticationProvider());
	}

	@Bean
	protected AuthenticationProvider unionidAuthenticationProvider() throws Exception{
		return new UnionidAuthenticationProvider();
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
	    return super.authenticationManagerBean();
	}

	@Bean
	protected CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Collections.singletonList("*"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST","HEAD", "DELETE", "PUT","OPTION"));
		configuration.setAllowedHeaders(Collections.singletonList("*"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
