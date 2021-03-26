package com.example.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 토큰에 저장된 유저 정보를 활용해야 하기 때문에
 * UserDetailsService를 상속받아 재정의 하는 과정을 진행행 */


@RequiredArgsConstructor
@Service
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * SpringSecurity는 UserDetails 객체를 통해 권한 정보를 관리하기 때문에
     * User 클래스에 UserDetails 를 구현하고 추가 정보를 재정의
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
    }
}