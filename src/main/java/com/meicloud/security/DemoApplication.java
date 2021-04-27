package com.meicloud.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author HuaDong
 * @date 2021/4/24 10:33
 */
@SpringBootApplication
@RestController
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    /**
     * 用户登录才可访问
     *
     * @return
     */
    @GetMapping("/hello")
    public String hello() {
        return "Hello Spring Security!";
    }

    /**
     * 用户登录才可访问
     *
     * @return
     */
    @GetMapping("/bye")
    public String bye() {
        return "Bye Spring Security!";
    }

    /**
     * 广告接口，匿名用户可以访问
     *
     * @return
     */
    @GetMapping("/ad")
    public String no() {
        return "妈妈再也不用担心我的学习！";
    }
}
