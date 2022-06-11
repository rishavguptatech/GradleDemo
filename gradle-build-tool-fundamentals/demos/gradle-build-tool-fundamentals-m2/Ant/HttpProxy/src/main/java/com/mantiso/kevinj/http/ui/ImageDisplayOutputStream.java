/*
 * ImageDisplayOutputStream.java
 *
 * Created on 11 September 2001, 14:28
 */

package com.mantiso.kevinj.http.ui;

import javax.swing.JTable;
import javax.swing.ImageIcon;

/** This output stream is associted with the 'image' MIME type.
 *
 * Gathers the data and turns it into an image to be displayed in a JTable
 *
 * @author Kevin Jones
 * @version 1.0
 */
public class ImageDisplayOutputStream extends DisplayOutputStream
{
    /** The table that will hold the images
     */    
    JTable imageTable;
    
    /** The raw data to be displayed
     */    
    byte[] data = null; 
    /** How much data has been read up to now
     */    
    int currentDataSize;
    /** Initial size of the data buffer
     */    
    static final int DATA_SIZE = 4096;
    /** How much data has been read into the <code>data</code> buffer
     */    
    int nCurrentPos;
    
    /** Creates new DisplayOutputStream
     * @param imageTable The JTable that will receive the image
     */
    public ImageDisplayOutputStream(JTable imageTable)
    {
        this.imageTable = imageTable;
        currentDataSize = DATA_SIZE;
    }
    
    /** Checks that the {@link #data data} buffer is large enough
     * @param spaceNeeded How much data is about to be read
     */    
    void checkDataSize(int spaceNeeded)
    {
        while((spaceNeeded + nCurrentPos) >= currentDataSize)
        {
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
        System.arraycopy(b, 0, data, nCurrentPos, b.length);
        nCurrentPos += b.length;
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
        currentDataSize = DATA_SIZE;
        data = new byte[currentDataSize];
        nCurrentPos = 0;
    }
    
    /** Creates a new <code>ImageIcon</code>, stores it in the
     * data model associated with the <code>JTable</code>, and resizes
     * the row to show this image
     */    
    public void endData()
    {
        synchronized(imageTable)
        {
            javax.swing.table.DefaultTableModel tm = (javax.swing.table.DefaultTableModel)imageTable.getModel();
            int nRows = tm.getRowCount();
            ImageIcon[] ii = new ImageIcon[1];
            ii[0] = new ImageIcon(data);
            tm.addRow(ii);
            imageTable.setRowHeight(nRows, ii[0].getIconHeight());
        }
    }        
}

