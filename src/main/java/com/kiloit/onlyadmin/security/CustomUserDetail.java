package com.kiloit.onlyadmin.security;
import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.kiloit.onlyadmin.database.entity.PermissionEntity;
import com.kiloit.onlyadmin.database.repository.PermissionRepository;
import com.kiloit.onlyadmin.database.repository.RoleRepository;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.kiloit.onlyadmin.database.entity.UserEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@Getter
@Setter
@Slf4j
public class CustomUserDetail implements UserDetails, Principal, Serializable {
    public static String type;
    private Long id;
    private String username;
    private String email;
    private String avatar;
    private String phone;
    private String address;
    private String roleName;
    private Long roleId;
    @JsonIgnore
    private String password;
    private Map<String, Object> attributes;
    private Set<String> permissions;
    private Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetail(UserEntity user,PermissionRepository permissionRepository) {
        this.id = user.getId();
        this.username= user.getUsername();
        this.email = user.getEmail();
        this.phone = user.getPhone();
        this.address =user.getAddress();
        this.avatar = user.getPhoto();
        this.roleId = user.getRole().getId();
        this.roleName= user.getRole().getName();
        this.password= user.getPassword();
        this.permissions= permissionRepository.findAllByRoleId(roleId);
        this.authorities=permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
    }
    public CustomUserDetail(JwtAuthenticationToken jwt) {

        Map<String, Object> claims = jwt.getTokenAttributes();

        this.id = (Long) claims.get("id");
        this.username = (String) claims.get("username");
        this.email = (String) claims.get("email");
        this.phone = (String) claims.get("phone");
        this.address = (String) claims.get("address");
        this.avatar = (String) claims.get("avatar");
        this.roleName = (String) claims.get("roleName");
        this.roleId = (Long) claims.get("roleId");

    }

    public static CustomUserDetail build(UserEntity user,PermissionRepository permissionRepository) {
        return new CustomUserDetail(user,permissionRepository);
    }

    public static CustomUserDetail build(JwtAuthenticationToken jwt) {
        return new CustomUserDetail(jwt);
    }



    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        if(type.equals("email")){
            return email;
        }
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
		return true;
	}

    @Override
	public boolean isAccountNonLocked() {
		return true;
	}

    @Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

    @Override
	public boolean isEnabled() {
		return true;
	}

    @Override
    public String getName() {
        return username;
    }
}
