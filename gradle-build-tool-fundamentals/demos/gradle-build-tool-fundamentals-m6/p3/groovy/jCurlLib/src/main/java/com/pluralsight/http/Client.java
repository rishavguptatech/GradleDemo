package com.pluralsight.http;

import org.apache.http.HttpStatus;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.message.BasicStatusLine;

public class Client {

    public StatusLine getImage(String url) {
        return new BasicStatusLine(new ProtocolVersion("", 1, 1), 200, "OK");
    }
}
