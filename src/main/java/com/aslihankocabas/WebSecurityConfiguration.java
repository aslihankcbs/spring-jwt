package com.aslihankocabas;

import com.aslihankocabas.auth.JwtTokenFilter;
import com.aslihankocabas.auth.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //tüm metotlarımızdan önce security'i devreye aldık
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtTokenFilter jwtTokenFilter;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    public void configurePasswordEncoder(AuthenticationManagerBuilder builder) throws Exception {
        //Spring security'e burada şunu demiş oluyoruz. Eğer bir user arıyorsan benim userDetailsService'imi kullan.
        //userDetailsService içerisindeki loadUserByUsername çalışacak. User var mı yok mu kontrol etmiş olacağız!
        builder.userDetailsService(userDetailsService).passwordEncoder(getBCryptPasswordEncoder());
    }

    //tekrar tekrar instance oluşturmak yerine bean olarak ürettik. Gerektiğinde bunları kullanıyoruz.

    @Bean
    public BCryptPasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests().antMatchers("/api/1.0/token").permitAll() //bu token ednpointi hariç adreslere authentication olmalı diye söylemiş olduk
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //security ile ilgili session üretimi yapmamaya başlıyor.
        // Her request içerisinde credential'ların olması gerektiğini söylüyoruz bu STATELESS ile

        http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class); //her request önünde bizim request filterimiz olacak
    }
}
