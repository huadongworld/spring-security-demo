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
public class MemberLoginDTO implements Serializable {

    public static final String FIELD_MEMBER_ID = "memberId";
    public static final String FIELD_BELONG_TO_ID = "belongToId";
    public static final String FIELD_UNION_ID = "unionid";
    public static final String FIELD_OPEN_ID = "openid";
    public static final String FIELD_USER_TYPE = "userType";
    public static final String FIELD_MOBILE = "mobile";

    public static final String FIELD_ACCESS_TOKEN = "Access-Token";
    public static final String FIELD_SET_ACCESS_TOKEN = "Set-Access-Token";

    /**
     * unionid
     */
    private String unionid;

    /**
     * openid
     */
    private String openid;

    /**
     * 会员ID
     */
    private Long memberId;

    /**
     * 登录手机号
     */
    private String mobile;

    public MemberLoginDTO(String unionid, String openid, Long memberId,String mobile) {
        this.unionid = unionid;
        this.openid = openid;
        this.memberId = memberId;
        this.mobile = mobile;
    }

    public MemberLoginDTO() {
    }

    public String sign(Algorithm algorithm, Date expireDate) {
        return JWT.create()
                .withSubject(unionid)
                .withClaim(FIELD_OPEN_ID, openid)
                .withClaim(FIELD_MEMBER_ID, memberId)
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
    public static MemberLoginDTO fromDecodeJWT(DecodedJWT jwt, Algorithm algorithm) {

        Assert.isTrue(StringUtils.isNotBlank(jwt.getSubject()), "Invalid Token");
        Assert.isTrue(jwt.getClaim(MemberLoginDTO.FIELD_OPEN_ID) != null, "Invalid Token");
        Assert.isTrue(jwt.getClaim(MemberLoginDTO.FIELD_MEMBER_ID) != null, "Invalid Token");
        Assert.isTrue(jwt.getClaim(MemberLoginDTO.FIELD_MOBILE) != null, "Invalid Token");

        String unionid = jwt.getSubject();
        String openid = jwt.getClaim(MemberLoginDTO.FIELD_OPEN_ID).asString();
        Long memberId = jwt.getClaim(MemberLoginDTO.FIELD_MEMBER_ID).asLong();
        String mobile = jwt.getClaim(MemberLoginDTO.FIELD_MOBILE).asString();

        JWTVerifier verifier = JWT.require(algorithm)
                .withSubject(unionid)
                .withClaim(MemberLoginDTO.FIELD_OPEN_ID, openid)
                .withClaim(MemberLoginDTO.FIELD_MEMBER_ID, memberId)
                .withClaim(MemberLoginDTO.FIELD_MOBILE, mobile)
                .build();

        verifier.verify(jwt.getToken());

        MemberLoginDTO scrmMemberLoginDTO = new MemberLoginDTO();
        scrmMemberLoginDTO.setUnionid(unionid);
        scrmMemberLoginDTO.setOpenid(openid);
        scrmMemberLoginDTO.setMemberId(memberId);
        scrmMemberLoginDTO.setMobile(mobile);

        return scrmMemberLoginDTO;
    }

    public static void main (String [] args) {
        Algorithm algorithm = Algorithm.HMAC256("MEICLOUD");
        Date expiredDate = new Date(System.currentTimeMillis() + 2592000L * 1000);
        MemberLoginDTO loginDTO = new MemberLoginDTO(
                "onAFS0bINoBKhWvtgYh-Jjy7dFjM",
                "oSLw4430mID1jvMIAk2AiYLaXl2o",
                576L,
                "15634211184");
        String token = loginDTO.sign(algorithm, expiredDate);
        System.out.println(token);
    }
}
