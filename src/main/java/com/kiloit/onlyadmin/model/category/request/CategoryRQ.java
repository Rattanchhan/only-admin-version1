package com.kiloit.onlyadmin.model.category.request;

import com.kiloit.onlyadmin.constant.MessageConstant;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class CategoryRQ {

    @NotNull(message = MessageConstant.CATEGORY.NAME_IS_NULL)
    private String name;
    @NotNull(message = MessageConstant.CATEGORY.MEDIA_ID_IS_NULL)
    private Long mediaId;

}
