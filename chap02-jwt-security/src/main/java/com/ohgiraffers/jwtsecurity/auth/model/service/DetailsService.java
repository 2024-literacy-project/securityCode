package com.ohgiraffers.jwtsecurity.auth.model.service;

import com.ohgiraffers.jwtsecurity.auth.model.DetailsUser;
import com.ohgiraffers.jwtsecurity.user.service.UserService;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DetailsService implements UserDetailsService {

    private final UserService userService;

    public DetailsService(UserService userService) {
        this.userService = userService;
    }

    /**
     * description. 로그인 요청 시 사용자의 id를 받아 DB에서 사용자 정보를 가져오는 메소드
     *
     * @param username the username identifying the user whose data is required.
     * @return UserDetails
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null || username.equals("")) {
            throw new AuthenticationServiceException(username + " is Empty!");
        } else {
            return userService.findUser(username)
                    .map(data -> new DetailsUser(Optional.of(data)))
                    .orElseThrow(() -> new AuthenticationServiceException((username)));
        }

    }
}
