package com.example.basic_authencation.controller;

import com.example.basic_authencation.model.TransactionRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import java.util.Base64;

@RestController
@RequestMapping("/secure")
@Slf4j
public class SecureCoreController {

    @Value("${security.user}")
    private String userTransaction;

    @Value("${security.password}")
    private String passTransaction;
    @PostMapping(value = "/get-transaction")
    public ResponseEntity<?> getTransaction(@RequestBody TransactionRequest request, HttpServletRequest http) {
        try {
            // Decode User and Password Basic Authorization
            String authorizationHeader = http.getHeader("Authorization");
            if (authorizationHeader != null && authorizationHeader.startsWith("Basic ")) {
                String base64Credentials = authorizationHeader.substring("Basic ".length());
                byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
                String credentials = new String(decodedBytes);
                String[] parts = credentials.split(":");
                String username = parts[0];
                String password = parts[1];

                // check authentication
                if (userTransaction.equals(username) && passTransaction.equals(password)) {
                    return ResponseEntity.ok().body(request.getDescription()); // Ở demo này chỉ trả về hello, thực tế có thể trả về object theo ý muốn
                } else {
                    return ResponseEntity.status(403).body("Sai tài khoản hoặc mật khẩu !");
                }
            }
            return ResponseEntity.status(401).body("Không có quyền truy cập !");
        } catch (Exception e) {
            log.error("Lỗi trong quá trình gọi tới server !", e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }


}
