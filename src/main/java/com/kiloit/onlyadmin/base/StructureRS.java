package com.kiloit.onlyadmin.base;

import com.kiloit.onlyadmin.constant.MessageConstant;
import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class StructureRS {
    private int status = HttpStatus.OK.value();
    private String message = MessageConstant.SUCCESSFULLY;
    private String messageKey = MessageConstant.SUCCESSFULLY.toLowerCase();
    private Object data;
    private PagingRS paging;

    public StructureRS() {
    }

    public<T> StructureRS(HttpStatus httpStatus,T data){
        this.status = httpStatus.value();
        this.data=data;
        this.status=httpStatus.value();
    }

    public <T> StructureRS(T data) {
        this.data = data;
    }

    public <T> StructureRS(T data, PagingRS paging) {
        this.data = data;
        this.paging = paging;
    }

    public StructureRS(HttpStatus httpStatus, String message) {
        this.status = httpStatus.value();
        this.message = message;
        this.messageKey = message.replaceAll("\\s+", "_").toLowerCase();
    }

    public <T> StructureRS(HttpStatus status, String message, T data) {
        this.status = status.value();
        this.message = message;
        this.messageKey = message.replaceAll("\\s+", "_").toLowerCase();
        this.data = data;
    }
}
