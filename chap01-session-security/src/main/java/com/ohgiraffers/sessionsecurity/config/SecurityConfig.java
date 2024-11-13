package com.ohgiraffers.sessionsecurity.config;

import com.ohgiraffers.sessionsecurity.common.UserRole;
import com.ohgiraffers.sessionsecurity.config.handler.AuthFailHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AuthFailHandler authFailHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(auth -> {
            // 해당하는 URL 은 로그인(인증이 되지 않은 사람도 들어갈 수 있다.)
            auth.requestMatchers("/auth/login", "/user/signup", "/auth/fail", "/", "/main").permitAll();
            // 해당하는 URL 은 권한이 ADMIN 인 사람만 들어갈 수 있다.
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole());
            // 해당하는 URL 은 권한이 USER 인 사람만 들어갈 수 있다.
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole());
            // 위에 작성하지 않은 URL 은 로그인(인증이 필요하다.) > 로그인페이지로 이동 됨.
            auth.anyRequest().authenticated();

        }).formLogin(login -> {
            // 실제로 로그인 기능을 만든 URL 기술
            login.loginPage("/auth/login");
            // form 태그의 id 입력하는 name 속성을 입력하는 공간
            login.usernameParameter("user");
            // form 태그의 pass 입력하는 name 속성을 입력하는 공간
            login.passwordParameter("pass");
            login.defaultSuccessUrl("/", true);
            login.failureHandler(authFailHandler);

        }).logout(logout -> {
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout"));
            logout.deleteCookies("JSESSIONID");
            logout.invalidateHttpSession(true);
            logout.logoutSuccessUrl("/");

        }).sessionManagement(session -> {
            session.maximumSessions(1);
            session.invalidSessionUrl("/");

        }).csrf(csrf -> csrf.disable());

        return http.build();
    }

}
