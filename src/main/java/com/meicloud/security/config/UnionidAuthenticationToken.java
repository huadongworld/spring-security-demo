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
public class UnionidAuthenticationToken extends AbstractAuthenticationToken {

    private String mobile;

    private String openId;

    private String unionId;

    private String nickName;

    private String gender;

    private String avatarUrl;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public UnionidAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String openId, String mobile, String unionId, String nickName, String gender, String avatarUrl) {
        super(authorities);
        this.openId = openId;
        this.mobile = mobile;
        this.unionId = unionId;
        this.nickName = nickName;
        this.gender = gender;
        this.avatarUrl = avatarUrl;
    }

    @Override
    public Object getCredentials() {
        return unionId;
    }

    @Override
    public Object getPrincipal() {
        return unionId;
    }
}
