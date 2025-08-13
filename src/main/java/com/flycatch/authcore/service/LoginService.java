package com.flycatch.authcore.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Map;

public interface LoginService {
   String login(String username, String password,HttpServletResponse response);
}
