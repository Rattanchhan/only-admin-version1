package com.kiloit.onlyadmin.database.entity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CurrentTimestamp;
import org.springframework.data.annotation.CreatedDate;

import java.time.Instant;

@Entity
@Table(name = "post_view")
@Getter
@Setter
public class PostViewEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private UserEntity user;
    @ManyToOne
    @JoinColumn(name = "post_id")
    private PostEntity post;
    @Column(name = "view_at", nullable = false, updatable = false)
    @CreatedDate
    @CurrentTimestamp
    private Instant viewAt;
}
