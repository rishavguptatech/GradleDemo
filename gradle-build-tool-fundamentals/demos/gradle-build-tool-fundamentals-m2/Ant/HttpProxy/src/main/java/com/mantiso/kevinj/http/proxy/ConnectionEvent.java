package com.mantiso.kevinj.http.proxy;

import java.util.EventObject;

/**
 * Created by IntelliJ IDEA.
 * User: kevinj
 * Date: 22-Oct-2003
 * Time: 16:45:54
 * To change this template use Options | File Templates.
 */
public class ConnectionEvent extends EventObject
{
    ConnectionData connectionData;

    public ConnectionEvent(Object source)
    {
        super(source);
    }

    public ConnectionData getConnectionData()
    {
        return connectionData;
    }

    public void setConnectionData(ConnectionData connectionData)
    {
        this.connectionData = connectionData;
    }
}
