/*
 * HexDisplayOutputStream.java
 *
 * Created on 10 September 2001, 15:07
 */

package com.mantiso.kevinj.http.ui;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;


import javax.swing.JTextArea;

/** A subclass of {@link DisplayOutputStream DisplayOutputStream}
 * that is associated with all MIME types and 
 * will format the data as hexadecimal bytes
 *
 * @author kevinj
 * @version 1.0
 */
public class HexDisplayOutputStream extends DisplayOutputStream
{
    static Logger logger = LogManager.getLogger(HexDisplayOutputStream.class);
    /** The data that will be displayed
     */    
    char output[];
    /** The raw data to be displayed
     */    
    byte[] data = null; 
    /** How much data has been read up to now
     */    
    int currentDataSize;
    /** How much data is in the <code>output</code> buffer
     */    
    int offset;
    /** Initial size of the data buffer
     */    
    static final int DATA_SIZE = 4096;
    // (each row starts '00000000: ' (10)
    // then has 32 chars, plus 16 embedded spaces (48)
    // one space between (1)
    // plus 16 chars plus 16 embedded spaces (32)
    // each line ends in '\r\n' (2)
    //     
    /** Length in bytes of the output row as it will appear in the
     * JTextArea window
     */    
    static final int ROW_LENGTH = 93;
    // where chars start after hex finishes
    /** An putput line will look like
     * prefix: hexdata characterdata
     *
     * This identifies where the character data starts
     */    
    static final int CHAR_OFFSET = 49;
    // Prefix is '00000000:'

    /** The prefix is the displayed offset at the start of a line
     * in the JTextArea window (i.e. 00000000: or 00000010:)
     */    
    static final int PREFIX_LENGTH = 10;

    /** How much data has been read into the <code>data</code> buffer
     */    
    int nCurrentPos;
    /** Hex bytes
     */    
    static char hex[] = { '0','1','2','3','4','5','6','7',
                           '8','9','A','B','C','D','E','F' };
    
   /** Creates new HexDisplayOutputStream
    * @param ha The JTextArea that will display the data
    */
    public HexDisplayOutputStream(JTextArea ha)
    {
        super(ha);
        currentDataSize = DATA_SIZE;
    }
    
    /** Checks that the {@link #data data} buffer is large enough
     * @param spaceNeeded How much data is about to be read
     */    
    void checkDataSize(int spaceNeeded)
    {
        while((spaceNeeded + nCurrentPos) >= currentDataSize)
        {
            logger.debug("checkDataSize: currentDateSize: " + currentDataSize);
            logger.debug("checkDataSize: data: " + data);
            currentDataSize *= 2;
            byte[] temp = new byte[currentDataSize];
            System.arraycopy(data, 0, temp, 0, nCurrentPos);
            data = temp;
        }
    }
    
    /** Store one byte in the <code>data</code> buffer
     * @param b the data
     * @throws java.io.IOException if there is an I/O error
     */    
    public void write(int b) throws java.io.IOException
    {
        checkDataSize(1);
        data[nCurrentPos++] = (byte)b;
    }
    
    /** Store this array of bytes in the <code>data</code> buffer
     * @param b the data
     * @throws java.io.IOException if there is an I/O error
     */    
    public void write(byte[] b) throws java.io.IOException
    {
        checkDataSize(b.length);
        if(b != null && data != null)
        {
            System.arraycopy(b, 0, data, nCurrentPos, b.length);
            nCurrentPos += b.length;
        }
    }
    
    /** Store len bytes at offest off from the byte array in the <code>data</code>
     * @param b the data
     * @param off offset into the array
     * @param len length of data
     * @throws java.io.IOException if there is an I/O error
     */    
    public void write(byte[] b, int off, int len) throws java.io.IOException
    {
        checkDataSize(len);
        System.arraycopy(b, off, data, nCurrentPos, len);
        nCurrentPos += len;
    }
    
    /** Psuedo constructor, re-initializes {@link #nCurrentPos nCurrentPos},
     * {@link #currentDataSize currentDataSize} and the {@link #data data} array
     */    
    public void startData()
    {
        logger.debug("startData");
        currentDataSize = DATA_SIZE;
        data = new byte[currentDataSize];
        nCurrentPos = 0;
    }
    
    /** Calls <code>formatData</code> to format the hex output.
     * Writes the data to the output window and write an 'end of data'
     * message.
     */    
    public void endData()
    {
        formatData();
        synchronized(textArea)
        {
            textArea.append(new String(output, 0, offset));
            textArea.append("\r\n-------------- End -----------------\r\n");
        }
    }    
    
    /** Formats the input data for display as hex data on the JTextArea.
     */    
    private void formatData()
    {
        // nCurrentPos / 16 to discover number of nRows
        int nRows = nCurrentPos / 16;
        
        // for the not complete last row
        nRows++;

        output = new char[(nRows) * ROW_LENGTH];

        int nRowLength = 0;
        
        offset = 0;

        // top 28 bits first then
        for (int j = 8; j > 1; j--)
        {
            // rotate each nibble in to calculate size
            int n = nRowLength >>> (4*j - 4);
            output[offset++] = hex[(n) & 0x0F];
        }
        // then bottom 4 bits
        output[offset++] = hex[(nRowLength) & 0x0F];
        output[offset++] = ':';
        output[offset++] = ' ';
 
        // -2 1, for the ++ after adding the space
        int current_char_offset = offset + CHAR_OFFSET - 1;
        output[current_char_offset++] = ' ';

        // loop for all the bytes that I've read in
        for(int count = 0; count < nCurrentPos; count++)
        {
            // high 4 bits
            char b1 = hex[data[count] >> 4 & 0x0F];
            // low 4 bits
            char b2 = hex[data[count] & 0x0F];
            
            output[offset++] = b1;
            output[offset++] = b2;
            output[offset++] = ' ';
            // 32 is 'space'
            if(data[count] > 32 && data[count] < 127)
            {
                output[current_char_offset++] = (char)data[count];
            }
            else
            {
                output[current_char_offset++] = '.';
            }                
            output[current_char_offset++] = ' ';          
            
            nRowLength++;
            // prepend count (00000100: etc) 
            if (nRowLength % 0x10 == 0)
            {
                // extra space between hex and characters
                offset = current_char_offset;

                // new line
                output[offset++] = '\r';
                output[offset++] = '\n';
                                
                // bottom char is always 0
                // top 28 bits first
                for (int j = 8; j > 1; j--)
                {
                    // rotate each nibble in to calculate size
                    int n = nRowLength >>> (4*j - 4);
                    output[offset++] = hex[(n) & 0x0F];
                }
                // then bottom 4 bits
                output[offset++] = hex[(nRowLength) & 0x0F];
                output[offset++] = ':';
                output[offset++] = ' ';
                current_char_offset = offset + CHAR_OFFSET - 1;
                output[current_char_offset++] = ' ';
            }
        }
    }
}