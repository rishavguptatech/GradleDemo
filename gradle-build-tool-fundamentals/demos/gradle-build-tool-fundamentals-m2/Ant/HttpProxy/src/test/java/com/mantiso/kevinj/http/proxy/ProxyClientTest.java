/*
 * Created by IntelliJ IDEA.
 * User: Kevin Jones
 * Date: 19-Jun-02
 * Time: 18:55:17
 * To change template for new class use 
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package com.mantiso.kevinj.http.proxy;

import com.mantiso.kevinj.http.ui.DisplayOutputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.mockito.Mockito.*;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.*;
import java.util.HashMap;

public class ProxyClientTest  {

    ProxyClient proxyClient;
    int _sendPort = 8888;
    String _originServer = "localhost";

    private DisplayOutputStream _dosAll;

    private DisplayOutputStream _dosImage;

    FakeServerSocket fss;

    @Before
    public void setUp() throws Exception {

        _dosImage = mock(DisplayOutputStream.class);

        _dosAll = mock(DisplayOutputStream.class);

        /* create a _server socket listening on port _sendPort and _server _originServer */
        fss = new FakeServerSocket(_sendPort, "test/data.in/clientImageData.dat");
        fss.start();
        HashMap registeredResponseListeners = new HashMap();

        registerListener("*", _dosAll, registeredResponseListeners);
        registerListener("image", _dosImage, registeredResponseListeners);

        // Proxy Client is going to connect to the origin _server

        proxyClient = new ProxyClient(null, _originServer, _sendPort, new FakeClientSocket(), 0);
        proxyClient.setListeners(null, registeredResponseListeners);
    }

    @Test
    public void testReadData() {
        proxyClient.run();

        verify(_dosImage).startData();
        verify(_dosImage).endData();
        verify(_dosAll).startData();
        verify(_dosAll).endData();

    }

    @Test
    public void testSetListeners() {
        proxyClient.run();
    }

    @After
    public void tearDown() throws Exception {
        fss.close();
    }

    void registerListener(String majorMIMEType, DisplayOutputStream os, HashMap registeredListeners) {
        java.util.HashSet displayOutputStreamSet = (java.util.HashSet) registeredListeners.get(majorMIMEType);
        if (displayOutputStreamSet == null) {
            displayOutputStreamSet = new java.util.HashSet();
            registeredListeners.put(majorMIMEType, displayOutputStreamSet);
        }
        displayOutputStreamSet.add(os);
    }

}

class FakeServerSocket extends Thread {
    /**
     * Port I'm listening on
     */
    int _listenPort;

    /**
     * _file to send to client
     */
    String _fileName;

    /**
     * Socket that this process can use to communicate with the user-agent
     */
    Socket serverSocket = null;

    /**
     * Create a _server socket and listen for incoming requests. As soon as the accept returns notify
     * any waiting threads
     */
    public void run() {
        synchronized (this) {
            ServerSocket ss = null;
            DataOutputStream os = null;
            FileInputStream fis = null;
            int i = 0;
            try {
                // listen for the incoming connection
                ss = new ServerSocket();
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress(_listenPort));

                // got the incoming connection
                serverSocket = ss.accept();

                fis = new FileInputStream(_fileName);
                os = new DataOutputStream(serverSocket.getOutputStream());
                int b;

                while ((b = fis.read()) != -1) {
                    os.write(b);
                    i++;
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (fis != null) fis.close();
                    if (os != null) {
                        os.write(-1);
                        os.close();
                    }
                    if (ss != null) {
                        ss.close();
                    }
                } catch (Exception ex) {
                    // do nothing
                }
            }
        }
    }

    public FakeServerSocket(int listenPort, String filename) {
        _listenPort = listenPort;
        File f = new File(filename);
        if (!f.exists()) {
            throw new IllegalArgumentException(filename + " does not exist");
        }

        _fileName = filename;
    }

    public void close() throws IOException {
        serverSocket.close();
    }
}

class FakeClientSocket extends Socket {
    String _fileName;

    public FakeClientSocket() {
    }

    public InputStream getInputStream() throws IOException {
        System.out.println("filename: " + _fileName);
        return new FileInputStream(_fileName);
    }

    public OutputStream getOutputStream() throws IOException {
        return new ByteArrayOutputStream();
    }
}
