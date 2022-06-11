package com.mantiso.kevinj.http.proxy;

import java.net.*;
import java.io.*;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * An instance of this class is used as the client by the proxy. It will forward
 * all requests to the origin server, and receive all responses. This class will
 * send the responses to all the registered output streams based on the MIME
 * type of the response.
 * <p>
 * It receives the name of the server and the number of the port to connect to,
 * along with a socket. The socket is the socket through which the response is
 * send back
 */
public class ProxyClient extends ProxyBase {

    static Logger logger = LogManager.getLogger(ProxyClient.class);

    Socket originSocket;

    // 0123456789012
    // HTTP/1.1 200 xxx
    /**
     * Where the response code starts in the HTTP status line
     */
    private static final int HTTP_RESPONSE_CODE_OFFSET_START = 9;

    /**
     * Where the response code ends in the HTTP status line
     */
    private static final int HTTP_RESPONSE_CODE_OFFSET_END = 12;

    /**
     * Port the origin server is listening on
     */
    private final int sendPort;

    /**
     * Name of server to connect to
     */
    private final String server;

    /**
     * Registered output streams
     */
    // MultiplexOutputStream clientReceiveMOS = null;
    /**
     * Hash map containing the _headers from the origin server. This is used
     * (for example) to discover the content length and the mime type.
     */
    // protected HashMap originHeaders;
    /**
     * Stream used to read data from the origin server
     */
    private InputStream isOrigin = null;

    /**
     * Stream used to write data to the origin server
     */
    private OutputStream osOrigin = null;

    /**
     * Stream used to write data back to the client
     */
    private OutputStream clientOutputStream = null;

    /**
     * Wrapper around the input stream
     */
    private java.io.BufferedInputStream _inputStream;

    /**
     * Wrapper around the input stream
     */
    // java.io.BufferedReader bufReader;
    /**
     * Socket that I'm connected to the original client on
     */
    private final Socket clientSocket;

    /**
     * The current response code from the origin server
     */
    private int responseCode = 0;

    /**
     * Constructor
     *
     * @param server       Name of server to connect to
     * @param sendPort     Port to connect to
     * @param clientSocket Socket on the base client that we send the response to
     * @throws UnknownHostException If the server doesn't exist
     * @throws IOException          If we are unable to create the socket connection to the
     *                              origin server
     *                              <p>
     *                              This constructor initialises the client object, saves away the parameters
     *                              passed to it and then opens the connection to the origin server
     */

    public ProxyClient(final HttpProxy httpProxy, final String server,
                       final int sendPort, final Socket clientSocket, int connectionId)
            throws  IOException {
        super(httpProxy, connectionId);
        logger.debug("ProxyClient: ctor: " + connectionId);
        this.server = server;
        this.sendPort = sendPort;
        this.clientSocket = clientSocket;
        clientOutputStream = clientSocket.getOutputStream();
        openConnectionToOrigin();
    }

    /**
     * Create a connection to the serverName and save away the Input and Output
     * streams needed to use that connection
     *
     * @throws IOException          if the socket cannot be opened
     * @throws UnknownHostException if the server doesn't exist
     */
    private void openConnectionToOrigin() throws UnknownHostException,
            IOException {
        originSocket = new Socket(server, sendPort);
        isOrigin = originSocket.getInputStream();
        osOrigin = originSocket.getOutputStream();
    }

    /**
     * Where the work is done
     * <p>
     * Create a buffered input stream to read from the origin server. Create an
     * output stream to write to the origin server Get the output stream to
     * write the origin server response back to the baes client Loop until the
     * response is done
     * </p>
     */
    public void run() {
        try {
            _inputStream = new java.io.BufferedInputStream(isOrigin);
            while (true) {
                logger.debug("ProxyClient: run");

                consumeOriginResponse();

                if (isContentLengthZero() == true) break;

                clearHeaders();
            }
        } catch (SocketClosed e) {
            // and ignore (flow of control exception - probably not a good idea)
        } catch (IOException e) {
            //todo: anything I can do about this other than log it?
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            try {
                originSocket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            ConnectionData data = new ConnectionData();
            data.setState("Done");
            data.setConnectionId(connectionId);
            if (httpProxy != null) {
                httpProxy.updateConnection(data);
            }
        }
    }

    /**
     * Check to see if the last response marked the end of the 'transaction' by
     * assigning a content length of 0
     * <p>
     * If so break out of the loop
     *
     * @return true if there is no further content to process
     */
    private boolean isContentLengthZero() {
        /*
         */
        String cl;
        if ((cl = (String) _headers.get(CONTENT_LENGTH)) != null) {
            if (Integer.parseInt(cl) == 0) {
                // no content
                return true;
            }
        }
        return false;
    }

    /**
     * This function reads the entire response from the origin server.
     * <p>
     * It starts with the status line, then the _headers and finally the data if
     * necessary
     *
     * @throws IOException if the read fails
     */
    private void consumeOriginResponse() throws IOException, SocketClosed {
        // read status line from origin server and send to client
        readHttpResponse(_inputStream, clientOutputStream);

        // read response _headers from origin server and send to client
        if (readHttpHeaders(_inputStream, clientOutputStream) == false) {
            logger.debug("readHttpHeaders == false");
        }

        // read data from origin server and send to client
        if (expectingData()) {
            logger.debug("expectingData");
            readData(_inputStream, clientOutputStream);
        }
        logger.debug("return");
    }

    /**
     * Helper function to return the output stream back to the creator of the
     * client.
     * <p>
     * The output stream is output stream from the origin server
     * <p>
     * The client uses this to write data directly to the origin server
     *
     * @return Returns the output stream back to the proxy server
     */
    public OutputStream getOutputStream() {
        return osOrigin;
    }

    /**
     * Read the response from the origin server
     * <p>
     * The response is parsed and the status code is removed. The status code is
     * needed to determine if the server is returning any data to us
     * <p>
     * Once read the status line is forwarded to the original client and any
     * registered listeners
     *
     * @param bis The buffered input stream containing the response
     * @param os  The MultiplexOutputStream that all registered listeners are
     *            called through
     * @throws IOException If data cannot be read from the input stream or written to
     *                     the multiplex output stream
     */
    private void readHttpResponse(final BufferedInputStream bis,
                                  final OutputStream os) throws IOException, SocketClosed {
        String strResponseLine = readLine(bis);
        logger.debug("ProxyClient: readHttpResponse: " + strResponseLine);
        if (strResponseLine != null) {
            responseCode = Integer.parseInt(strResponseLine.substring(
                    HTTP_RESPONSE_CODE_OFFSET_START,
                    HTTP_RESPONSE_CODE_OFFSET_END));
            writeHeaders(os, strResponseLine.getBytes());
            writeHeaders(os, _crlf);
        } else {
            // above call to readLine blocks until server closes socket
            // want to throw an exception to show end of connection
            throw new SocketClosed("Unable to read request line");
        }
    }

    /**
     * Certain HTTP response codes ensure that the response has no content.
     *
     * @return true if the response may have content
     */
    private boolean expectingData() {
        if ((responseCode == 304) || (responseCode == 204)
                || (responseCode >= 100 && responseCode < 200))
            return false;
        else
            return true;
    }

}