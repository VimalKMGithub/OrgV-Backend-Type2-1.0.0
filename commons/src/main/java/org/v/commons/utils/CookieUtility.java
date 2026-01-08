package org.v.commons.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

public class CookieUtility {
    public static void addHttpOnlyCookie(HttpServletResponse response,
                                         String name,
                                         String value,
                                         String sameSite,
                                         String path,
                                         long maxAge) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                //.secure(true)          // enable when HTTPS
                .sameSite(sameSite)
                .path(path)
                .maxAge(maxAge)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public static void removeHttpOnlyCookie(HttpServletResponse response,
                                            String name,
                                            String sameSite,
                                            String path) {
        ResponseCookie cookie = ResponseCookie.from(name, "")
                .httpOnly(true)
                //.secure(true)          // enable when HTTPS
                .sameSite(sameSite)
                .path(path)
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public static String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
