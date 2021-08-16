package com.meicloud.oauth.config;

import com.meicloud.oauth.service.OAuthClientDetailsService;
import com.meicloud.oauth.service.impl.OAuthClientDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * @author HuaDong
 * @since 2021/8/16 13:58
 */
@Configuration
public class BeanConfig {

    @Autowired
    private RedisConnectionFactory connectionFactory;

    /**
     * 这里使用 Redis 存储 Token
     *
     * @return
     */
    @Bean(name = "tokenStore")
    public TokenStore tokenStore() {
        RedisTokenStore tokenStore = new RedisTokenStore(connectionFactory);
        // 设置存储 Token 信息的前缀
        tokenStore.setPrefix("api:client:token:");
        return tokenStore;
    }

    /**
     * 如果需要使用 Spring Expression 表达式，需要配置这个 Bean（资源服务器校验接口权限需要配置这个）
     *
     * @param applicationContext
     * @return
     */
    @Bean
    public OAuth2WebSecurityExpressionHandler oAuth2WebSecurityExpressionHandler(ApplicationContext applicationContext) {
        OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
        expressionHandler.setApplicationContext(applicationContext);
        return expressionHandler;
    }

    /**
     * 配置 oAuthClientDetailsService Bean，
     *
     * @return
     */
    @Bean(name = "oAuthClientDetailsService")
    public OAuthClientDetailsService oAuthClientDetailsService() {
        return new OAuthClientDetailsServiceImpl();
    }
}
