package com.example.msauth.model.jwt;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccessTokenClaimSet implements Serializable {
    private static final long serialVersionUID = 1L;

    private Long userId;
    private String iss;

    @JsonProperty("exp")
    private Date expirationTime;

    @JsonProperty("iat")
    private Date createdTime;

}
