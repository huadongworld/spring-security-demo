package com.meicloud.oauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * OAuth2.0 资源服务配置
 *
 * @author HuaDong
 * @since 2021/6/29 10:22
 */
@EnableResourceServer
@Configuration
@Slf4j
public class OAuthResourceConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler;

    /**
     * 资源ID，唯一标识一个资源，oauth_client_details 的 resource_ids 需要有这个才能访问当前资源
     */
    public static final String RESOURCE_ID = "security_oauth_demo_resource_id";

    /**
     * 白名单
     */
    protected String[] permitUrls = new String[]{"/ad"};

    @Override
    public void configure(ResourceServerSecurityConfigurer resources)throws Exception{
        resources
                .resourceId(RESOURCE_ID)
                // tokenStore 定义在 OAuthorizationServerConfig
                .tokenStore(tokenStore)
                .expressionHandler(oAuth2WebSecurityExpressionHandler);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS).permitAll()
                .antMatchers(permitUrls).permitAll()
                .anyRequest().access("@oAuthClientDetailsService.hasPermission(request, authentication)")
                .and()
                .httpBasic()
                .and().csrf().disable();
    }

}
