package com.meicloud.security.config;

import lombok.Data;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 登录认证Token
 *
 * @author HuaDong
 * @since 2021/4/24 20:29
 */
@Data
public class UserAuthenticationToken extends AbstractAuthenticationToken {

    /**
     * 登录账号/手机号
     */
    private String mobile;

    /**
     * 登录密码
     */
    private String password;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public UserAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String mobile, String password) {
        super(authorities);
        this.mobile = mobile;
        this.password = password;
    }

    @Override
    public Object getCredentials() {
        return mobile;
    }

    @Override
    public Object getPrincipal() {
        return mobile;
    }
}
