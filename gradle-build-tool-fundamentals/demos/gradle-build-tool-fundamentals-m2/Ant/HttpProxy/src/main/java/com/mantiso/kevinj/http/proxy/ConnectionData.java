package com.mantiso.kevinj.http.proxy;

import java.util.Date;
import java.net.Socket;

/**
 * Created by IntelliJ IDEA.
 * User: kevinj
 * Date: 21-Oct-2003
 * Time: 10:29:04
 * To change this template use Options | File Templates.
 */
public class ConnectionData
{
    private String state;
    private Date dateStarted;
    private String requestHost;
    private String targetHost;
    private String request;
    private Socket serverSocket;
    private int listenPort;
    private int connectionId;

    public ConnectionData()
    {
        state = "";
        requestHost = "";
        requestHost = "";
        targetHost = "";
        dateStarted = new Date(0);
    }

    public String getState()
    {
        return state;
    }

    public void setState(String state)
    {
        this.state = state;
    }

    public Date getDateStarted()
    {
        return dateStarted;
    }

    public void setDateStarted(Date dateStarted)
    {
        this.dateStarted = dateStarted;
    }

    public String getRequestHost()
    {
        return requestHost;
    }

    public void setRequestHost(String requestHost)
    {
        this.requestHost = requestHost;
    }

    public String getTargetHost()
    {
        return targetHost;
    }

    public void setTargetHost(String targetHost)
    {
        this.targetHost = targetHost;
    }

    public String getRequest()
    {
        return request;
    }

    public void setRequest(String request)
    {
        this.request = request;
    }

    public String toString()
    {
        return state + "-" + dateStarted.toString() + "-" + requestHost + "-"
                + targetHost + "-" + request + "-" + serverSocket + "-" + connectionId;
    }

    public void setServerSocket(Socket serverSocket)
    {
        this.serverSocket = serverSocket;
    }

    public Socket getServerSocket()
    {
        return serverSocket;
    }

    public void setListenPort(int listenPort)
    {
        this.listenPort = listenPort;
    }

    public int getListenPort()
    {
        return listenPort;
    }

    public int getConnectionId()
    {
        return connectionId;
    }

    public void setConnectionId(int connectionId)
    {
        this.connectionId = connectionId;
    }
}
