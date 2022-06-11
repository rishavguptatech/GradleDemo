package com.mantiso.kevinj.http.proxy;

import java.net.*;
import java.io.*;

/** An instance of this class will act as the _server for this
 * proxy.
 *
 * It will receive the data from the base client and pass that
 * data on to origin _server and any registered listeners.
 */
public class ProxyServer extends ProxyBase
{
    /** The socket this _server will receive HTTP requests on
     */
    Socket _serverSocket;
    /** Output stream to the origin _server
     */
    OutputStream _osOrigin = null;

    /** This is the input stream from the base client that
     * originated the request.
     */
    java.io.BufferedInputStream _inputStream;
    private boolean bFirstRequestFromClient;


    /** Constructor for the proxy _server. This also saves the _server
     * name away for later use.
     * @param server Name of _server to connect to
     * @param serverSocket Socket that we are communicating with the base
     * client on
     * @param os OutputStream to the origin _server
     */
    public ProxyServer(HttpProxy httpProxy, String server, int serverPort, Socket serverSocket, OutputStream os, int connectionId)
    {
        super(httpProxy, connectionId);
        logger.debug("ProxyClient: ctor: " + connectionId);
        this._serverSocket = serverSocket;
        _serverName = server;
        this._serverPort = serverPort;
        _osOrigin = os;
    }

    /** This is where the _server side work will be done.
     *
     * The code will read data from the input stream and send it to any listening client. The
     * listening client could be the origin _server or maybe a UI to display the incoming
     * data.
     *
     * The _server will write back to the client and data returned from the origin _server.
     *
     */
    public void run()
    {
        try
        {
            _inputStream = new java.io.BufferedInputStream(_serverSocket.getInputStream());
            bFirstRequestFromClient = true;
            while (true)
            {
                logger.debug("ProxyServer: run");
                if(consumeClientRequest() == false)
                    break;
                clearHeaders();
                bFirstRequestFromClient = false;
            }
        }
        catch (IOException ioe)
        {
        }
        finally
        {
            logger.debug("ProxyServer: finish");
            try
            {
                _serverSocket.close();
            }
            catch (IOException e)
            {
                logger.debug("ProxyServer: run", e);  //To change body of catch statement use Options | File Templates.
            }
        }
    }

    /** Read the request line, _headers and data from the request.
     * @throws IOException If the input or output streams are broken
     * @return true if all the calls succeed
     */
    boolean consumeClientRequest() throws IOException
    {
        if (readHttpRequest(_inputStream, _osOrigin) == false)
            return false;

        if (readHttpHeaders(_inputStream, _osOrigin) == false)
            return false;
        readData(_inputStream, _osOrigin);

        return true;
    }

    /** Helper function to read the HTTP request line
     * @param bis InputStream containing the current HTTP data
     * @param os OutputStream to the origin to write the data to
     * @throws IOException If the input stream or the output stream fails
     * @return true if the call succeeds
     */
    boolean readHttpRequest(BufferedInputStream bis, OutputStream os) throws IOException
    {
        String strRequestLine = readLine(bis);

        if(bFirstRequestFromClient)
            notifyListenersOfNewRequestLine(strRequestLine);

        if (strRequestLine != null)
        {
            writeHeaders(os, strRequestLine.getBytes());
            writeHeaders(os, _crlf);
            return true;
        }
        return false;
    }

    private void notifyListenersOfNewRequestLine(String strRequestLine)
    {
        ConnectionData data = new ConnectionData();
        data.setRequest(strRequestLine);
        data.setConnectionId(connectionId);
        httpProxy.updateConnection(data);
    }

    /** Override the call to {@link ProxyBase#readData(BufferedInputStream, OutputStream) readData}.
     * The _server only reads data if the client sends a
     * ContentLength header, the base class method will also try
     * and read data if there is no header, that would cause the
     * _server to block
     * @param bis InputStream containing the current HTTP data
     * @param outputStream Output stream to write the data to
     * @throws IOException If the input stream or the output stream fails
     * @return true if there is a content_length header
     */
    boolean readData(BufferedInputStream bis, OutputStream outputStream) throws IOException
    {
        // check for a contentLength header
        String cl;
        notifyAllListeners(DATA_START);
        try
        {
            if ((cl = (String) _headers.get(CONTENT_LENGTH)) != null)
            {
                return readContentLengthData(bis, Integer.parseInt(cl), outputStream);
            }
            else
            {
                return false;
            }
        }
        finally
        {
            notifyAllListeners(DATA_END);
        }
    }

}
