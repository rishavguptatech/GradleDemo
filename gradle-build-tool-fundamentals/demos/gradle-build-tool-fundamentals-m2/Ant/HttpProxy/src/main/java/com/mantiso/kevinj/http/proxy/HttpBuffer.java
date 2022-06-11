package com.mantiso.kevinj.http.proxy;

import java.io.ByteArrayOutputStream;

/**
 * Created by IntelliJ IDEA.
 * User: kevinj
 * Date: 21-Oct-2003
 * Time: 11:48:14
 * To change this template use Options | File Templates.
 */
public class HttpBuffer
{
    String mimeType;
    ByteArrayOutputStream inputBuffer;
    ByteArrayOutputStream outputBuffer;


    public HttpBuffer()
    {
        inputBuffer = new ByteArrayOutputStream();
        outputBuffer = new ByteArrayOutputStream();
    }

    public String getMimeType()
    {
        return mimeType;
    }

    public void setMimeType(String mimeType)
    {
        this.mimeType = mimeType;
    }

    public ByteArrayOutputStream getInputBuffer()
    {
        return inputBuffer;
    }

    public ByteArrayOutputStream getOutputBuffer()
    {
        return outputBuffer;
    }
}
