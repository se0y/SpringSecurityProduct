package kr.ac.hansung.cse.hellospringdatajpa.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    private UserDetailsService customUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    private static final String[] PUBLIC_MATCHERS = { // 로그인하지 않아도 접근 가능한 정적 리소스 및 공용 경로들
            "/webjars/**",
            "/css/**",
            "/js/**",
            "/images/**",
            "/about/**",
            "/contact/**",
            "/error/**",
            "/console/**"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception { // Spring Security의 필터 체인을 수동 설정하는 메서드
        http
                .authorizeHttpRequests(authz -> authz // 요청별 접근 권한
                        .requestMatchers(PUBLIC_MATCHERS).permitAll()
                        .requestMatchers("/", "/home", "/signup").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN") // /admin/**는 ROLE_ADMIN 사용자만 가능
                        .anyRequest().authenticated()  // 그 외 모든 요청은 로그인 필요
                )
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .defaultSuccessUrl("/products") // 로그인 성공 시 /products로 리다이렉트
                        .failureHandler((request, response, exception) -> {
                            String errorMessage;
                            if (exception instanceof UsernameNotFoundException) {
                                errorMessage = "존재하지 않는 이메일입니다.";
                            } else {
                                errorMessage = "이메일 또는 비밀번호가 올바르지 않습니다.";
                            }
                            request.getSession().setAttribute("errorMessage", errorMessage);
                            response.sendRedirect(request.getContextPath() + "/home");
                        })
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                    Authentication authentication) throws IOException, ServletException {
                                HttpSession session = request.getSession();
                                if (authentication != null && authentication.getName() != null) {
                                    session.setAttribute("successMessage", authentication.getName() + "님, 로그아웃에 성공했습니다.");
                                }
                                response.sendRedirect(request.getContextPath() + "/home");
                            }
                        })
                        .permitAll()
                )
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedPage("/accessDenied") // 권한 부족(403 등) 발생 시 이동할 페이지 지정
                )
                .userDetailsService(customUserDetailsService); // 로그인 시 사용자 정보를 어디서 가져올지 지정
               /* .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**"));*/

        return http.build(); // 위에서 구성한 보안 설정을 Spring Security에 반영
    }
}
