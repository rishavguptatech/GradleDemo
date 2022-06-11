package com.mantiso.kevinj.http.proxy;

import java.util.Date;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * IncomingClientThread is a helper class used to listen for the incoming client
 * connection.
 * 
 * @author Kevin Jones
 */
public class IncomingClientThread extends Thread
{
    Logger logger = LogManager.getLogger(IncomingClientThread.class);

    /**
     * Port the _server will listen on
     */
    int listenPort;

    int sendPort;

    String serverName;
    HttpProxy httpProxy;

    /**
     * Socket that this process can use to communicate with the user-agent
     */
    Socket serverSocket = null;

    /**
     *
     * @param proxy
     */
    IncomingClientThread(HttpProxy proxy)
    {
        this.httpProxy = proxy;
        this.listenPort = httpProxy.getListenPort();
        this.sendPort = httpProxy.getSendPort();
        this.serverName = httpProxy.getServer();
    }

    /**
     * Create a _server socket and listen for incoming requests. As soon as the
     * accept returns notify any waiting threads
     */
    public void run()
    {
        synchronized (this)
        {
            ServerSocket ss = null;
            try
            {
                ss = new ServerSocket(listenPort);
            }
            catch (IOException e)
            {
                e.printStackTrace(); // To change body of catch statement use
                                        // Options | File Templates.
                return;
            }
            while (true)
            {
                try
                {
                    // listen for the incoming connection
                    // got the incoming connection
                    serverSocket = ss.accept();
                    logger.debug("Just accepted serverName socket");

                    ConnectionData connectionData = new ConnectionData();

                    connectionData.setDateStarted(new Date());
                    connectionData.setRequest("");
                    connectionData.setRequestHost(serverSocket.getInetAddress()
                            .getHostAddress());
                    connectionData.setState("Active");
                    connectionData.setTargetHost(serverName);
                    connectionData.setServerSocket(serverSocket);
                    connectionData.setListenPort(listenPort);
                    httpProxy.addNewConnection(connectionData);
                }
                catch (Exception e)
                {
                    try
                    {
                        if (ss != null) ss.close();
                        ss = new ServerSocket(listenPort);
                    }
                    catch (Exception e1)
                    {
                        e1.printStackTrace();
                        return;
                    }
                    e.printStackTrace();
                }
            }
        }
    }

}
