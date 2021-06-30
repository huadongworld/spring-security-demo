package com.meicloud.sentinel.controller;

import com.alibaba.csp.sentinel.Entry;
import com.alibaba.csp.sentinel.SphU;
import com.alibaba.csp.sentinel.context.ContextUtil;
import com.alibaba.csp.sentinel.slots.block.BlockException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author HuaDong
 * @since 2021/6/8 14:04
 */
@Slf4j
@RestController
@RequestMapping("/sentinel")
public class SentinelPrincipleController {

    @GetMapping("/principle1")
    public void principle1(HttpServletRequest request, HttpServletResponse response) {

        try {
            ContextUtil.enter("sentinel_myself_content", "");

            Entry entry = null;
            try {
                entry = SphU.entry("principle1");

                log.info("principle1 演示执行成功√√√");

                int i = 10;
                while (i-- > 0) {
                    this.getInfo();
                }

            } catch (BlockException ex) {
                log.error("principle1 演示被限流了×××");

            } finally {
                if (entry != null) {
                    entry.exit();
                }
            }

        } finally {
            ContextUtil.exit();
        }
    }

    private void getInfo() {
        Entry entryEntry = null;
        try {
            entryEntry = SphU.entry("getInfo");
            log.info("getInfo 执行成功√√√");

        } catch (BlockException ex) {
            log.error("getInfo 被限流了×××");

        } finally {
            if (entryEntry != null) {
                entryEntry.exit();
            }
        }
    }

    @GetMapping("/principle2")
    public void principle2(HttpServletRequest request, HttpServletResponse response) {

        try {
            ContextUtil.enter("sentinel_myself_content", "");

            Entry entry = null;
            try {
                entry = SphU.entry("principle2");

                log.info("principle2 演示执行成功√√√");

            } catch (BlockException ex) {
                log.error("principle2 演示被限流了×××");

            } finally {
                if (entry != null) {
                    entry.exit();
                }
            }

        } finally {
            ContextUtil.exit();
        }
    }

}
