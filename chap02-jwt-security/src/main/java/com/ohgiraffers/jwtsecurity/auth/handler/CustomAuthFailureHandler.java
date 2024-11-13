package com.ohgiraffers.jwtsecurity.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

/**
 * 사용자 로그인 실패 시 실패 요청을 커스텀 하기 위한 핸들러 클래스
 */
/*
 *   [ 패키지 구조 ]
 *   AuthenticationFailureHandle(interface) -> SimpleUrlAuthenticationFail(class) -> AuthFailHandler
 *   우리는 AuthenticationFilureHandler 구현해야 하지만 기존에 구현되어 있는 SimpleUrlAuthenticationFail 상속 받아
 *   응답 메시지와 페이지 경로를 설정할 수 있게 하도록 재정의를 하는 것이다.
 *   페이지 경로와 커스텀을 할 수 있도록 만들어주는 메서드는 setDefaultFailureUrl("경로") 메서드 이다.
 * */
public class CustomAuthFailureHandler implements AuthenticationFailureHandler {

    /**
     * 사용자의 잘못된 로그인 시도를 커스텀 하기 위한 핸들러 메소드
     *
     * @param request   사용자 요청 개체
     * @param response  서버 응답값
     * @param exception 발생한 오류를 담는 개체
     */
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        JSONObject jsonObject;
        String failMsg;

        if (exception instanceof AuthenticationServiceException) {
            //사용자의 로그인 또는 인증 처리 과정에서 문제가 발생한다.
            failMsg = "존재하지 않는 사용자입니다.";

        } else if(exception instanceof BadCredentialsException) {
            // BadCredentialsException 오류는 사용자의 아이디가 DB에 존재하지 않는 경우 비밀번호가 맞지 않는 경우 발생한다.
            failMsg = "아이디 또는 비밀번호가 틀립니다.";

        } else if(exception instanceof LockedException) {
            // 계정이 잠긴 경우 발생하는 오류이다.
            failMsg ="잠긴 계정입니다.";

        } else if(exception instanceof DisabledException) {
            // 비활성화 된 계정에서 발생한다.
            failMsg ="비활성화된 계정입니다.";

        } else if(exception instanceof AccountExpiredException) {
            // 계정 만료시 발생하는 에러
            failMsg ="만료된 계정입니다.";

        } else if(exception instanceof CredentialsExpiredException) {
            // 자격 증명이 만료되는 경우 발생
            failMsg = "자격증명이 만료되었습니다.";
        } else if (exception instanceof AuthenticationCredentialsNotFoundException) {
            //보안 컨텍스트에 인증 객체가 존재하지 않거나 인증 정보가 없는 상태에서 보안처리된 리소스에 접근하는 경우 발생
            failMsg = "인증 요청이 거부되었습니다.";
        }else if (exception instanceof UsernameNotFoundException) {
            // db에 사용자의 정보가 없는 경우 발생하는 오류이다
            failMsg = "존재하지 않는 이메일 입니다.";
        }else{
            failMsg = "정의되있는 케이스의 오류가 아닙니다.";
        }

        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("failType",failMsg);

        jsonObject = new JSONObject(resultMap);

        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();
    }

}