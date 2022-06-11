package com.mantiso.kevinj.http.proxy;

import com.develop.io.MultiplexOutputStream;

import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Iterator;

import com.mantiso.kevinj.http.ui.ProxyPanel;

/**
 * The HttpProxy class will listen for incoming connections on {@link #_listenPort _listenPort} and will
 * forward the requests to {@link #_sendPort _sendPort}.
 * It will create a <code>ServerSocket</code> for the user-agent to connect to. This is done by
 * the <code>start</code> method creating a thread to listen for incoming connections.
 * <p>
 * Once the user-agent has connected, the listening thread notifies the <code>HttpProxy</code> class
 * which is listening inside the <code>serverListen</code> method.
 *
 * @author Kevin Jones
 * @version 0.1
 */
public class HttpProxy {
    private ArrayList connectionListeners = new ArrayList();

    private ConnectionListener _connectionListener;


    /**
     * The port this _server listens on
     */
    protected int _listenPort;

    /**
     * The port the proxy will connect to
     */
    protected int _sendPort;

    /**
     * The _server the proxy will connect to
     */
    protected String _server;

    /**
     * Thread used to listen for incoming requests
     */
    protected IncomingClientThread _listenThread = null;

    /**
     * Socket used to send data to the _server
     */
    protected Socket _clientSocket = null;

    /**
     * The incoming HTTP request line
     */
    protected String _strRequestLine = null;


    InputStream _isServer = null;
    OutputStream _osServer = null;
    /**
     * Socket used to read data from the user-agent
     */
    protected Socket serverSocket = null;

    public ConnectionListener getConnectionListener() {
        return _connectionListener;
    }

    public int getListenPort() {
        return _listenPort;
    }

    public int getSendPort() {
        return _sendPort;
    }

    public String getServer() {
        return _server;
    }

    public IncomingClientThread getListenThread() {
        return _listenThread;
    }

    public Socket getClientSocket() {
        return _clientSocket;
    }

    public String getRequestLine() {
        return _strRequestLine;
    }

    public InputStream getIinputStreamServer() {
        return _isServer;
    }

    public OutputStream getOutputStreamServer() {
        return _osServer;
    }

    public Socket getServerSocket() {
        return serverSocket;
    }

    public HttpProxy(int listenPort) {
        _listenPort = listenPort;
    }

    /**
     * Create an HttpProxy object to listen for connections and
     * forward the recived data to the destination _server
     *
     * @param listenPort The port this proxy will listen on as a _server
     * @param sendPort   The port the proxy will connect to
     * @param server     The _server the proxy will connect to
     */
    public HttpProxy(int listenPort, int sendPort, String server) {
        _listenPort = listenPort;
        _sendPort = sendPort;
        _server = server;
    }

    /**
     * Start the client and _server for this proxy instance.
     *
     * @return <code>true</code> if both client and _server were started,
     * <code>false</code> otherwise
     */
    public boolean start() {
        try {
            createServer();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }


    /**
     * Create and start the thread that will listen for the incoming socket connection
     */
    private void createServer() {
        _listenThread = new IncomingClientThread(this);
        _listenThread.start();
    }

    public void addNewConnection(ConnectionData data) {
        synchronized (connectionListeners) {
            for (Iterator it = connectionListeners.iterator(); it.hasNext(); ) {
                ConnectionListener connectionListener = (ConnectionListener) it.next();
                ConnectionEvent event = new ConnectionEvent(this);
                event.setConnectionData(data);
                connectionListener.addNewConnection(event);
            }
        }
    }

    public void updateConnection(ConnectionData data) {
        synchronized (connectionListeners) {
            for (Iterator it = connectionListeners.iterator(); it.hasNext(); ) {
                ConnectionListener connectionListener = (ConnectionListener) it.next();
                ConnectionEvent event = new ConnectionEvent(this);
                event.setConnectionData(data);
                connectionListener.updateConnection(event);
            }
        }
    }

    public void addConnectionListener(ProxyPanel proxyPanel) {
        synchronized (connectionListeners) {
            connectionListeners.add(proxyPanel);
        }
    }

    public void startProxies(String targetHost,
                             int listenPort,
                             Socket serverSocket,
                             int connectionId,
                             MultiplexOutputStream requestHeaderListeners,
                             HashMap registeredRequestListeners,
                             MultiplexOutputStream responseHeaderListeners,
                             HashMap registeredResponseListeners) throws IOException, UnknownHostException {
        ProxyClient pc = null;
        ProxyServer ps = null;
        pc = new ProxyClient(this, targetHost, getSendPort(), serverSocket, connectionId);
        ps = new ProxyServer(this, targetHost, listenPort, serverSocket, pc.getOutputStream(), connectionId);
        ps.setListeners(requestHeaderListeners, registeredRequestListeners);
        ps.start();
        pc.setListeners(responseHeaderListeners, registeredResponseListeners);
        pc.start();

    }
}

