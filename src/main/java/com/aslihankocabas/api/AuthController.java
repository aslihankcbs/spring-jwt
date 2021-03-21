package com.aslihankocabas.api;

import com.aslihankocabas.auth.TokenManager;
import com.aslihankocabas.auth.Credentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    private TokenManager tokenManager;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/api/1.0/token")
    public ResponseEntity<String> login(@RequestBody Credentials credentials) {  //token dönecek
        try{
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(credentials.getUsername(), credentials.getPassword()));
            return ResponseEntity.ok(tokenManager.generateToken(credentials.getUsername()));
        }catch (Exception e){
            throw e;
        }
    }
}
