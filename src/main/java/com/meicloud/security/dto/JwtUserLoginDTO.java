package com.meicloud.security.dto;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Date;

/**
 * 会员登录对象
 *
 * @author HuaDong
 * @since 2021/4/24 21:19
 */
@Data
public class JwtUserLoginDTO implements Serializable {

    public static final String FIELD_USER_ID = "userId";
    public static final String FIELD_MOBILE = "mobile";
    public static final String FIELD_NICKNAME = "NICKNAME";

    public static final String FIELD_ACCESS_TOKEN = "Access-Token";
    public static final String FIELD_SET_ACCESS_TOKEN = "Set-Access-Token";

    /**
     * 用户ID
     */
    private Long userId;

    /**
     * 昵称
     */
    private String nickname;

    /**
     * 手机号
     */
    private String mobile;

    public JwtUserLoginDTO(Long userId, String nickname, String mobile) {
        this.userId = userId;
        this.nickname = nickname;
        this.mobile = mobile;
    }

    public JwtUserLoginDTO() {
    }

    /**
     * 签名，生成JWT令牌
     *
     * @param algorithm
     * @param expireDate
     * @return
     */
    public String sign(Algorithm algorithm, Date expireDate) {
        return JWT.create()
                .withSubject("subject_" + String.valueOf(userId))
                .withClaim(FIELD_USER_ID, userId)
                .withClaim(FIELD_NICKNAME, nickname)
                .withClaim(FIELD_MOBILE, mobile)
                .withExpiresAt(expireDate)
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    /**
     * 验证令牌有效性并返回用户对象
     *
     * @param jwt
     * @param algorithm
     * @return
     * @throws JWTVerificationException
     */
    public static JwtUserLoginDTO fromDecodeJWT(DecodedJWT jwt, Algorithm algorithm) {

        Assert.isTrue(StringUtils.isNotBlank(jwt.getSubject()), "Invalid Token");
        Assert.isTrue(jwt.getClaim(JwtUserLoginDTO.FIELD_USER_ID) != null, "Invalid Token");
        Assert.isTrue(jwt.getClaim(JwtUserLoginDTO.FIELD_NICKNAME) != null, "Invalid Token");
        Assert.isTrue(jwt.getClaim(JwtUserLoginDTO.FIELD_MOBILE) != null, "Invalid Token");

        String userIdStr = jwt.getSubject();
        Long userId = jwt.getClaim(JwtUserLoginDTO.FIELD_USER_ID).asLong();
        String nickname = jwt.getClaim(JwtUserLoginDTO.FIELD_NICKNAME).asString();
        String mobile = jwt.getClaim(JwtUserLoginDTO.FIELD_MOBILE).asString();

        JWTVerifier verifier = JWT.require(algorithm)
                .withSubject(userIdStr)
                .withClaim(JwtUserLoginDTO.FIELD_USER_ID, userId)
                .withClaim(JwtUserLoginDTO.FIELD_NICKNAME, nickname)
                .withClaim(JwtUserLoginDTO.FIELD_MOBILE, mobile)
                .build();

        verifier.verify(jwt.getToken());

        JwtUserLoginDTO jwtUserLoginDTO = new JwtUserLoginDTO();
        jwtUserLoginDTO.setUserId(userId);
        jwtUserLoginDTO.setMobile(mobile);

        return jwtUserLoginDTO;
    }
}
