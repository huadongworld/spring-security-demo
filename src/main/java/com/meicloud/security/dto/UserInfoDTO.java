package com.meicloud.security.dto;

import lombok.Data;

import java.io.Serializable;

/**
 * @author HuaDong
 * @since 2021/4/26 17:14
 */
@Data
public class UserInfoDTO implements Serializable {
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

    /**
     * 密码
     */
    private String password;

    public UserInfoDTO() {
    }

    public UserInfoDTO(Long userId, String nickname, String mobile, String password) {
        this.userId = userId;
        this.nickname = nickname;
        this.mobile = mobile;
        this.password = password;
    }
}
