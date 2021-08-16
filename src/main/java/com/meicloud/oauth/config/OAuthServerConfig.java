package com.meicloud.oauth.config;

import com.meicloud.oauth.service.OAuthClientDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * OAuth2 认证服务配置
 *
 * @author HuaDong
 * @since 2021/6/28 11:03
 */
@Configuration
@EnableAuthorizationServer
public class OAuthServerConfig extends AuthorizationServerConfigurerAdapter{

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private OAuthClientDetailsService oAuthClientDetailsService;

    @Autowired
    private TokenStore tokenStore;

    /**
     * accessToken 过期时间
     */
    private int accessExpireTimeInSecond = 2592000;

    /**
     * refreshToken 过期时间
     */
    private int refreshExpireTimeInSecond = 86400;

    /**
     * 生成 token 的处理
     */
    @Primary
    @Bean
    public DefaultTokenServices defaultTokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        // 是否支持 refreshToken
        tokenServices.setSupportRefreshToken(true);
        // 是否复用 refreshToken，不复用的话是每次都会刷新token
        tokenServices.setReuseRefreshToken(true);
        // token 有效期自定义设置，默认12小时
        tokenServices.setAccessTokenValiditySeconds(accessExpireTimeInSecond);
        // 默认 30 天，这里修改
        tokenServices.setRefreshTokenValiditySeconds(refreshExpireTimeInSecond);
        return tokenServices;
    }

    /**
     * 配置 ClientDetailsServiceConfigurer
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails((ClientDetailsService)oAuthClientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        // 开启 /oauth/token_key 验证端口无权限访问
        oauthServer.tokenKeyAccess("permitAll()");
        // 开启 /oauth/check_token 验证端口认证权限访问
        oauthServer.checkTokenAccess("permitAll()");
        // 开启后请求需要带上 client_id client_secret
        oauthServer.allowFormAuthenticationForClients();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(tokenStore)
                .authenticationManager(authenticationManager)
                .tokenServices(defaultTokenServices())
                // 获取token支持get方式和post方式
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
    }
}