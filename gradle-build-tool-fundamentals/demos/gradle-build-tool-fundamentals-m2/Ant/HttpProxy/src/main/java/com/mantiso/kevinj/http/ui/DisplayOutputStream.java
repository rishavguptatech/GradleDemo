/*
 * DisplayOutputStream.java
 *
 * Created on 10 September 2001, 17:17
 */

package com.mantiso.kevinj.http.ui;
import javax.swing.*;
import java.io.OutputStream;

/** This is the base class for the various streams used to
 * gather data that will be displayed by the UI.
 *
 * Subclasses of this class should override at least the
 * {@link #write(byte[]) write(byte[])} method to provide an
 * efficient write mechanism
 *
 * @author kevinj
 * @version 1.0
 */
public class DisplayOutputStream extends OutputStream
{

    protected JTextArea textArea;

    protected DisplayOutputStream()
    {
    }


    /** Creates a new DisplayOutputStream that will forward to the
     * stream passed in as a parameter
     * @param ta JTextArea
     */    

    public DisplayOutputStream(JTextArea ta)
    {
        textArea = ta;
    }


    /** Called when the output stream is about to start
     * receiving data
     */    
    public void startData(){

    }

    /** Called when the output stream has received the last of its
     * data
     */    
    public void endData(){}

    /** Close the stream
     * @throws java.io.IOException if an I/O error occurs
     */    
    public void close() throws java.io.IOException
    {
    }
    
    /** Flush the stream
     * @throws java.io.IOException if an I/O error occurs
     */    
    public void flush() throws java.io.IOException
    {
    }

    /** Writes b.length bytes from the specified byte array to this output stream.
     * The general contract for write(b) is that it should have exactly the same effect as the call write(b, 0, b.length).
     * @param b The data
     * @throws java.io.IOException if an I/O error occurs.
     */    
    public void write(byte[] b) throws java.io.IOException
    {
        for(int i = 0; i < b.length; i++)
            write(b[i]);
    }

    /** Writes len bytes from the specified byte array starting at offset off to this output stream. The general contract for write(b, off, len) is that some of the bytes in the array b are written to the output stream in order; element b[off] is the first byte written and b[off+len-1] is the last byte written by this operation.
     * The write method of OutputStream calls the write method of one argument on each of the bytes to be written out. Subclasses are encouraged to override this method and provide a more efficient implementation.
     *
     * If b is null, a NullPointerException is thrown.
     *
     * If off is negative, or len is negative, or off+len is greater than the length of the array b, then an IndexOutOfBoundsException is thrown.
     *
     *
     * @param b the Data
     * @param off the start offset in the data
     * @param len the length of the data
     * @throws java.io.IOException if an I/O error occurs
     */    
    public void write(byte[] b, int off, int len) throws java.io.IOException
    {
        byte[] temp = new byte[len];
        System.arraycopy(b, off, temp, 0, len);
        write(temp);
    }

    /** Write a single byte of data
     * @param b the data
     * @throws java.io.IOException if an I/O error occurs
     */    
    public void write(int b) throws java.io.IOException
    {
    }
}
