package com.mantiso.kevinj.http.proxy;

import java.util.EventListener;

/**
 * Created by IntelliJ IDEA.
 * User: kevinj
 * Date: 21-Oct-2003
 * Time: 10:33:20
 * To change this template use Options | File Templates.
 */
public interface ConnectionListener extends EventListener
{
    void addNewConnection(ConnectionEvent evt);
    void updateConnection(ConnectionEvent evt);
}
