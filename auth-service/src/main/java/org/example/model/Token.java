package org.example.model;

import lombok.Builder;
import lombok.Data;
import org.json.JSONObject;

@Builder
@Data
public class Token {

    private JSONObject header;
    private JSONObject payload;
    private String signature;

}
