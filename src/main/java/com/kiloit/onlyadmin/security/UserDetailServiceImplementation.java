package com.kiloit.onlyadmin.security;
import java.util.Optional;
import com.kiloit.onlyadmin.database.repository.PermissionRepository;
import org.apache.coyote.BadRequestException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.kiloit.onlyadmin.constant.MessageConstant;
import com.kiloit.onlyadmin.database.entity.UserEntity;
import com.kiloit.onlyadmin.database.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailServiceImplementation implements UserDetailsService {
    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        String type="";
        try {
            Optional<UserEntity> user = userRepository.findUserOrEmail(userName);
            if(user.isEmpty()) throw new BadRequestException(MessageConstant.USER.USER_NOT_FOUND);
            else{
                if(userName.contains("@gmail.com")) type="email";
                CustomUserDetail.type = type;
                return  CustomUserDetail.build(user.get(),permissionRepository);
            }
        } catch (BadRequestException e) {
            throw new UsernameNotFoundException(e.getMessage());
        }
    }
    
}
