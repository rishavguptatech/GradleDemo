package com.mantiso.kevinj.http.proxy;

import java.io.*;
import java.util.*;


import com.develop.io.*;
import com.mantiso.kevinj.http.ui.DisplayOutputStream;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Base class for the client and _server portions of the proxy.
 * <p>
 * This class knows how to read HTTP _headers and consume HTTP
 * data and forward that to both the final endpoint of the
 * communication and any registered listeners to request and/or
 * response data
 */
public abstract class ProxyBase extends Thread {

    HttpProxy httpProxy;
    int connectionId;

    static Logger logger = LogManager.getLogger(ProxyBase.class);

    /**
     * Content length header name
     */
    static final String CONTENT_LENGTH = "CONTENT-LENGTH";
    /**
     * Host header name
     */
    static final String HOST = "HOST";
    /**
     * Transfer type header name
     */
    static final String TRANSFER_TYPE = "TRANSFER-ENCODING";
    /**
     * Content type header name
     */
    static final String CONTENT_TYPE = "CONTENT-TYPE";
    /**
     * Flag passed to {@link #notifyAllListeners(int) notifyAllListeners} function specifying
     * if the data is about to be presented to the listeners
     */
    static final int DATA_START = 1;
    /**
     * Flag passed to {@link #notifyAllListeners(int) notifyAllListeners} function specifying
     * if the data output has ended
     */
    static final int DATA_END = 2;

    /**
     * _headerListeners are output streams that will be sent all
     * the Http _headers they are interested in. The listeners will
     * be want either the request or response _headers
     */
    MultiplexOutputStream _headerListeners = null;
    /**
     * _registeredTypeListeners contains a mapping of major MIME
     * type against {@link DisplayOutputStream DisplayOutputStream}. The MIME type
     * could be '*', 'text' or 'image'
     */
    HashMap _registeredTypeListeners = null;
    /**
     * Holds the major MIME type of the data currently being
     * processed
     */
    String _contentType = "";
    /**
     * This is the name of the _server we are acting as a proxy for.
     * The {@link ProxyServer ProxyServer} class sets this value. A client will
     * connect to http://localhost (say), so this value is used to
     * fake up the HTTP 'Host:' header so that downstream HTTP 1.1
     * proxys and servers get what they think should be the
     * right value.
     */
    String _serverName;
    /**
     * This is the port number of the _server we are acting as a proxy for.
     * The {@link ProxyServer ProxyServer} class sets this value. A client will
     * connect to http://localhost:8888 (say), so this value is used to
     * fake up the HTTP 'Host:' header so that downstream HTTP 1.1
     * proxys and servers get what they think should be the
     * right value.
     */
    int _serverPort;
    /**
     * The Current HTTP header being processed. Getting and using
     * the name and value of the current HTTP header is done in
     * separate methods, this acts as a bridge between those
     * methods.
     */
    String _currentHeader;
    /**
     * Contains all the _headers for this request/response, the
     * header name is the key, and the header value is the data
     */
    protected HashMap _headers = null;

    final protected byte[] _crlf = "\r\n".getBytes();

    /** default constructor
     */

    /**
     * @param httpProxy
     * @param connectionId
     */
    public ProxyBase(HttpProxy httpProxy, int connectionId) {
        this.httpProxy = httpProxy;
        this.connectionId = connectionId;
        _headers = new HashMap();
    }

    /**
     * Reads the HTTP message a line at a time extract the current
     * name and value of the header being processed. This function
     * loops until it finds an empty line signifying the end of the
     * _headers. Calls {@link #addHeader(String) addHeader} to store the _headers in a
     * HashMap
     *
     * @param bis      InputStream containing the HTTP _headers
     * @param osServer OutputStream to send the _headers to
     * @return true if the function succeeds
     * @throws IOException If one of the streams fails
     */
    boolean readHttpHeaders(BufferedInputStream bis, OutputStream osServer) throws IOException {
        String header = readLine(bis);
        if (header == null)
            return false;

        /* stores _headers in collection and forwards to appropriate endpoint */
        while (header != null && header.length() != 0) {
            addHeader(header);
            // special case Host: header
            sendHeaders(osServer, header);
            header = readLine(bis);
        }
        ;

        writeHeaders(osServer, _crlf);

        _contentType = (String) _headers.get(CONTENT_TYPE);
        return true;
    }

    /**
     * Adds a header to the {@link #_headers _headers} HashMap. The passed in
     * string looks like 'name: value', and is parsed accordingly
     * The HOST header is treated specially, as we are 'faking' being the
     * host.
     *
     * @param header String containing the HTTP header to add
     */
    void addHeader(String header) {
        String value = null;
        logger.debug("addHeader:" + header);

        // header lines can continue, if a line starts with a space then it's a continuation
        if ((header.charAt(0) == ' ')
                || (header.charAt(0) == '\t')) {
            logger.debug("space in header");
            String headerValue = (String) _headers.get(_currentHeader.toUpperCase());
            headerValue += header;
            _headers.put(_currentHeader.toUpperCase(), headerValue);
        } else {
            _currentHeader = header.substring(0, header.indexOf(':'));
            if (_currentHeader.equals("Host") == true)
                value = _serverName;
            else
                value = header.substring(header.indexOf(':') + 1);

            _headers.put(_currentHeader.toUpperCase(), value.trim());
        }
    }

    /**
     * @param osServer
     * @param header
     * @throws IOException
     */
    void sendHeaders(OutputStream osServer, String header) throws IOException {
        if (_currentHeader.equals(HOST) == true) {
            processHostHeader(osServer, header);
        } else {
            processNonHostHeaders(osServer, header);
        }
    }

    /**
     * @param osServer
     * @param header
     * @throws IOException
     */
    void processHostHeader(OutputStream osServer, String header) throws IOException {
        writeHeaders(osServer, "Host: ".getBytes());
        writeHeaders(osServer, _serverName.getBytes());
        if (_serverPort != 80) {
            writeHeaders(osServer, ":".getBytes());
            writeHeaders(osServer, new Integer(_serverPort).toString().getBytes());
        }
        writeHeaders(osServer, _crlf);
    }

    /**
     * @param osServer
     * @param header
     * @throws IOException
     */
    void processNonHostHeaders(OutputStream osServer, String header) throws IOException {
        writeHeaders(osServer, header.getBytes());
        writeHeaders(osServer, _crlf);
    }

    /**
     * Empties the {@link #_headers _headers} Hashmap and sets the
     * {@link #_contentType _majorContentType} to its default value.
     */
    void clearHeaders() {
        _headers.clear();
        _contentType = "";
    }

    /**
     * This is called to notify all listeners that they are about
     * to be sent data, or that the data stream has ended
     *
     * @param notification Starting to send data, or just finished sending
     *                     data
     */
    void notifyAllListeners(int notification) {
        // get set of listeners that care about any MIME type
        if (_registeredTypeListeners != null) {
            synchronized (_registeredTypeListeners) {
                HashSet displayOutputStreamSet = (HashSet) _registeredTypeListeners.get("*");
                notifyListeners(displayOutputStreamSet, notification);

                // get set of listeners that care about the current MIME type
                if (_contentType != null) {
                    int ndx = _contentType.indexOf('/');
                    String majorContentType = _contentType.substring(0, ndx);
                    displayOutputStreamSet = (HashSet) _registeredTypeListeners.get(majorContentType);
                    notifyListeners(displayOutputStreamSet, notification);


                    // todo: why look for ';' is this for the qos stuff?
                    ndx = _contentType.indexOf(';');
                    if (ndx != -1) {
                        String contentType = _contentType.substring(0, ndx);
                        displayOutputStreamSet = (HashSet) _registeredTypeListeners.get(contentType);
                        notifyListeners(displayOutputStreamSet, notification);
                    }
                }
            }
        }
    }

    /**
     * @param displayOutputStreamSet
     * @param notification
     */
    private void notifyListeners(HashSet displayOutputStreamSet, int notification) {
        if (displayOutputStreamSet != null) {
            // get each listeners output stream
            Iterator it = displayOutputStreamSet.iterator();
            while (it.hasNext()) {
                DisplayOutputStream displayOutputStream = (DisplayOutputStream) it.next();
                synchronized (displayOutputStream) {
                    if (notification == DATA_START) {
                        displayOutputStream.startData();
                    } else if (notification == DATA_END) {
                        displayOutputStream.endData();
                    }
                }
            }
        }
    }

    /**
     * Reads the data that makes up the current request or
     * response.
     *
     * @param bis InputStream containg the data
     * @param os  OutputStream to send the data to
     * @return true if we read all the data succesfully
     * @throws IOException If either stream fails
     */
    boolean readData(BufferedInputStream bis, OutputStream os) throws IOException {
        String cl;
        String enc;
        // notify all listeners that we are about to send them data
        notifyAllListeners(DATA_START);
        try {
            // do we have a content length header
            if ((cl = (String) _headers.get(CONTENT_LENGTH)) != null) {
                // get the value
                int contentLength = Integer.parseInt(cl);                // and read the data
                logger.debug("ContentLength: " + contentLength);
                return readContentLengthData(bis, contentLength, os);
            } else if ((enc = (String) _headers.get(TRANSFER_TYPE)) != null) {
                // do we have 'chunked' encoding
                if ("chunked".equals(enc)) {
                    // read the line containing the chunk size
                    String chunkSizeLine = readLine(bis);
                    // and forward it to all interested parties

                    writeData(os, chunkSizeLine.getBytes());
                    writeData(os, _crlf);

                    // extract the initial chunksize
                    int chunkSize = Integer.parseInt(chunkSizeLine, 16);
                    logger.debug("ChunkSize: " + chunkSize);

                    readChunkSizeData(chunkSize, bis, os);
                    return true;
                }
                return false;
            } else {
                // if we get to here I have no Content-Length and no encoding
                // so we read to the end of the stream
                byte[] buf = new byte[1024];
                int n = 0;
                while ((n = bis.read(buf)) > 0) {
                    writeData(os, buf, 0, n);
                }
                return true;
            }
        } finally {
            // tell all listeners that we have no more data
            notifyAllListeners(DATA_END);
        }
    }

    /**
     * @param chunkSize
     * @param bis
     * @param os
     * @throws IOException
     */
    private void readChunkSizeData(int chunkSize, BufferedInputStream bis, OutputStream os) throws IOException {
        String chunkSizeLine;
        // get all chunks data
        while (chunkSize != 0) {
            byte[] buf = new byte[chunkSize];
            // read as much as I can
            int n = bis.read(buf);
            logger.debug("Initial Chunk Read: " + n);
            writeData(os, buf, 0, n);

            // more to read for this chunk?
            while (n < chunkSize) {
                int size = bis.read(buf, 0, chunkSize - n);
                n += size;
                logger.debug("Chunk Read: " + n);
                writeData(os, buf, 0, size);
            }

            // read next chunksize
            // chunked data is followed by a CRLF - read that
            readLine(bis);

            // and write it to the stream
            writeData(os, _crlf);

            // read the next line containing the chunk size
            chunkSizeLine = readLine(bis);
            // and parse out the value
            chunkSize = Integer.parseInt(chunkSizeLine, 16);

            // forward the chunk size
            writeData(os, chunkSizeLine.getBytes());
            writeData(os, _crlf);
            // and loop if the value isn't 0
        }
        // last chunk has a CRLF read this off the i/stream and write it
        readLine(bis);
        writeData(os, _crlf);
    }

    /**
     * Helper function to read HTTP data based on the contentLength
     *
     * @param bis           InputStream containg the data
     * @param contentLength length of data to read
     * @param os            OutputStream to send the data to
     * @return true if we read all the data succesfully
     * @throws IOException If either stream fails
     */
    boolean readContentLengthData(BufferedInputStream bis, int contentLength, OutputStream os)
            throws IOException {
        byte[] buf = new byte[contentLength];
        int size = bis.read(buf, 0, contentLength);
        logger.debug("size: " + size);

        // forward data
        while (size < contentLength) {
            int n = bis.read(buf, size, contentLength - size);
            size += n;
            logger.debug("size: " + size);
        }
        writeData(os, buf);
        return true;
    }

    /**
     * Write the HTTP body to any listeners registerd with either
     * the MIME type currently being processed, or to listeners
     * registered for all MIME types
     *
     * @param buf Data to write
     * @throws IOException If any of the output streams are broken
     */
    void writeToRegisteredListeners(byte[] buf) throws IOException {
        if (_registeredTypeListeners != null) {
            synchronized (_registeredTypeListeners) {
                HashSet displayOutputStreamSet = (HashSet) _registeredTypeListeners.get("*");
                if (displayOutputStreamSet != null) {
                    writeToOutputStreams(displayOutputStreamSet, buf);
                    flush(displayOutputStreamSet);
                }

                String majorContentType = "";
                // get set of listeners that care about the current MIME type
                if (_contentType != null) {
                    int ndx = _contentType.indexOf('/');
                    majorContentType = _contentType.substring(0, ndx);

                    displayOutputStreamSet = (HashSet) _registeredTypeListeners.get(majorContentType);
                    if (displayOutputStreamSet != null) {
                        writeToOutputStreams(displayOutputStreamSet, buf);
                        flush(displayOutputStreamSet);
                    }

                    // todo: why look for ';' is this for the qos stuff?
                    ndx = _contentType.indexOf(';');
                    if (ndx != -1) {
                        String contentType = _contentType.substring(0, ndx);
                        displayOutputStreamSet = (HashSet) _registeredTypeListeners.get(contentType);
                        if (displayOutputStreamSet != null) {
                            writeToOutputStreams(displayOutputStreamSet, buf);
                            flush(displayOutputStreamSet);
                        }
                    }
                }
            }
        }
    }

    /** Retrieve the set of
     * {@link DisplayOutputStream DisplayOutputStream} from the
     * {@link #_registeredTypeListeners _registeredTypeListeners}
     * HashMap data member
     * @param hashSet Set of {@link #_registeredTypeListeners _registeredTypeListeners}
     * @return Set of {@link DisplayOutputStream DisplayOutputStream}
     */
/*
    private final synchronized DisplayOutputStream[] getContainedStreams(HashSet hashSet)
    {
        DisplayOutputStream result[] = new DisplayOutputStream[hashSet.size()];
        return (DisplayOutputStream[])hashSet.toArray(result);
    }
*/

    /**
     * Helper function that retrives the set of output streams
     * passed in and actually writes the data.
     *
     * @param hs Set of {@link DisplayOutputStream DisplayOutputStream}
     * @param b  Data to write
     * @throws IOException If any of the streams are broken
     */
    public void writeToOutputStreams(HashSet hs, byte b[]) throws IOException {
        Iterator it = hs.iterator();
        while (it.hasNext()) {
            DisplayOutputStream displayOutputStream = (DisplayOutputStream) it.next();
            synchronized (displayOutputStream) {
                displayOutputStream.write(b);
            }
        }
/*
        DisplayOutputStream streams[] = getContainedStreams(hs);
        int length = streams.length;
        for (int n = 0; n < length; n++)
            streams[n].write(b);
*/
    }

    /**
     * Flushes each of the listener output streams
     *
     * @param hs Set of {@link DisplayOutputStream DisplayOutputStream}
     * @throws IOException If any of the output streams are broken
     */
    public void flush(HashSet hs) throws IOException {
        Iterator it = hs.iterator();
        while (it.hasNext()) {
            DisplayOutputStream displayOutputStream = (DisplayOutputStream) it.next();
            synchronized (displayOutputStream) {
                displayOutputStream.flush();
            }
        }
/*
        OutputStream streams[] = getContainedStreams(hs);
        int length = streams.length;
        for (int n = 0; n < length; n++)
            streams[n].flush();

*/
    }

    /**
     * Process the input buffer and call the helper
     * {@link #writeToRegisteredListeners(byte[]) writeToRegisteredListeners}
     *
     * @param buf    The input data
     * @param offset the offset into the buffer
     * @param length the length of data
     * @throws IOException If any of the output streams are broken
     */
    void writeToRegisteredListeners(byte[] buf, int offset, int length) throws IOException {
        byte[] dest = new byte[length];
        System.arraycopy(buf, 0, dest, offset, length);
        writeToRegisteredListeners(dest);
        return;
    }

    /**
     * BufferedInputStream doesn't have a readLine method, as HTTP
     * headers (and other data) are passed as lines then this
     * helper provides simple readLine functionallity
     *
     * @param is InputStream to read the data from
     * @return The line just read
     * @throws IOException If the stream is broken
     */
    String readLine(BufferedInputStream is) throws IOException {
        byte[] readLineBuffer = new byte[1024];

        int i = -1;
        int ret = -1;
        do {
            i++;
            ret = is.read(readLineBuffer, i, 1);
        } while ((char) readLineBuffer[i] != '\n' && ret != -1);

        if (ret == -1)
            return null;

        String str = new String(readLineBuffer, 0, i - 1);
        return str;
    }

    /**
     * This method stores the listeners passed in as part of the
     * proxy initialization
     *
     * @param headerListeners         Set of listeners interested in the _headers
     * @param registeredTypeListeners Set of listeners interested in data
     */
    public void setListeners(MultiplexOutputStream headerListeners, HashMap registeredTypeListeners) {
        this._headerListeners = headerListeners;
        this._registeredTypeListeners = registeredTypeListeners;
    }


    /**
     * @param osServer
     * @param data
     * @throws IOException
     */
    void writeHeaders(OutputStream osServer, byte[] data) throws IOException {
        osServer.write(data);
        osServer.flush();
        if (_headerListeners != null) {
            _headerListeners.write(data);
            _headerListeners.flush();
        }
    }

    /**
     * @param os
     * @param data
     * @throws IOException
     */
    private void writeData(OutputStream os, byte[] data) throws IOException {
        os.write(data);
        os.flush();

        writeToRegisteredListeners(data);
    }

    /**
     * @param os
     * @param buf
     * @param offset
     * @param length
     * @throws IOException
     */
    void writeData(OutputStream os, byte[] buf, int offset, int length) throws IOException {
        byte[] dest = new byte[length];
        System.arraycopy(buf, 0, dest, offset, length);
        writeData(os, dest);
        return;
    }

}
