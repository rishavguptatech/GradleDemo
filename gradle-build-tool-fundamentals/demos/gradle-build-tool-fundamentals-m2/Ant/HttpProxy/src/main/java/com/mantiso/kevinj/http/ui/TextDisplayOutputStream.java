/*
 * TextDisplayOutputStream.java
 *
 * Created on 10 September 2001, 14:45
 */
package com.mantiso.kevinj.http.ui;

import java.io.IOException;
import javax.swing.JTextArea;

/** A subclass of {@link DisplayOutputStream DisplayOutputStream}
 * that is associated with text MIME types and 
 * display the text in a <code>JTextArea</code>

 * @author kevinj
 * @version 1.0
 */
public class TextDisplayOutputStream extends DisplayOutputStream
{
    /** Creates new DisplayOutputStream
     * @param ta JTextArea that will display the text
     */
    public TextDisplayOutputStream(JTextArea ta)
    {
        super(ta);
    }
    /** Append one byte to the JTextArea
     * @param b the data
     * @throws IOException if there is an I/O problem
     */    
    public void write(int b) throws java.io.IOException
    {
        synchronized(textArea)
        {
            textArea.append("" + b);
        }
    }
    
    /** Append byte array to the JTextArea
     * @param b the data
     * @throws IOException if there is an I/O problem
     */    
    public void write(byte[] b) throws java.io.IOException
    {
        String str = new String(b);
        synchronized(textArea)
        {
            textArea.append(str);
        }
    }
    
    /** Append byte array from offset off, of length len to the JTextArea
     * @param b the data
     * @param off offset into the array where the data starts
     * @param len length of the data
     * @throws IOException if there is an I/O problem
     */    
    public void write(byte[] b, int off, int len) throws IOException
    {
        String str = new String(b, off, len);
        synchronized(textArea)
        {
            textArea.append(str);
        }
    }

    public void startData()
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    /** Called when the output stream has received the last of its
     * data
     */    
    public void endData()
    {
        synchronized(textArea)
        {
            textArea.append("\r\n");
        }
    }
  
}
