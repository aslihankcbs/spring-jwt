package com.aslihankocabas.auth;

import java.io.IOException;
import java.util.ArrayList;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

//gelen her requesti kontrol edecek.
//OncePerRequestFilterı extends alarak her request'e bir defa uygulanacak
@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Autowired
    private TokenManager tokenManager;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        /**
         * Bearer 123sdasds123
         */
        final String authHeader = httpServletRequest.getHeader("Authorization");

        String username = null;
        String token = null;


        if (authHeader != null && authHeader.contains("Bearer")) {
            token = authHeader.substring(7);
            try {
                username = tokenManager.getUsernameToken(token);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }

        /**
         SecurityContextHolder.getContext().getAuthentication() == null bu şu anlama geliyor. Bu kullanıcı daha önce bu token ile sisteme girmemişse
         */

        if (username != null && token != null
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (tokenManager.tokenValidate(token)) {
                UsernamePasswordAuthenticationToken upassToken =
                        new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
                upassToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest)); //gelen request'i verdik.
                SecurityContextHolder.getContext().setAuthentication(upassToken);
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
        // daha önce loginse springcontext içerisinde biliniyorsa işleme devam etsin
        // değilse if çalışacak, initialize edilmesi lazım
    }
}
