package com.meicloud.mall.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

/**
 * 卖家
 *
 * @author HuaDong
 * @since 2021/5/9 18:14
 */
@RestController
@RequestMapping("/seller")
public class SellerController {

    /**
     * 卖家接单
     *
     * @return
     */
    @GetMapping("/order:receive")
    @RolesAllowed("SELLER")
    public String receiveOrder() {
        return "卖家接单啦！";
    }

    /**
     * 卖家订单发货
     *
     * @return
     */
    @GetMapping("/order:deliver")
    @Secured("SELLER")
    public String deliverOrder() {
        return "卖家发货啦！";
    }
}