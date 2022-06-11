/*
 * Created by IntelliJ IDEA.
 * User: Kevin Jones
 * Date: 19-Jun-02
 * Time: 18:09:25
 * To change template for new class use 
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package com.mantiso.kevinj.http.ui;

import java.io.IOException;
import java.io.FileInputStream;

import junit.framework.Test;
import junit.framework.TestSuite;
import junit.framework.TestCase;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

public class ImageDisplayOutputStreamTest extends TestCase
{
    JTable _table;

    public ImageDisplayOutputStreamTest(String name)
    {
        super(name);
    }

    protected void setUp() throws Exception
    {
        _table = new JTable();
        _table.setModel(
                new javax.swing.table.DefaultTableModel(
                        new Object[][]
                        {
                        },
                        new String[]
                        {
                            "Images"
                        }
                )
        {
            Class[] types = new Class[]
            {
                javax.swing.ImageIcon.class
            };
            boolean[] canEdit = new boolean[]
            {
                false
            };

            public Class getColumnClass(int columnIndex)
            {
                return types[columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex)
            {
                return canEdit[columnIndex];
            }
        });
    }

    public void testSmallGif()
    {
        try
        {
            addGif(new String[]{"test/data.in/small.gif"});

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    public void testLargeGif()
    {
        try
        {
            addGif(new String[]{"test/data.in/large.gif"});
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    public void testMultipleGifs()
    {
        try
        {
            addGif(new String[]{"test/data.in/large.gif", "test/data.in/small.gif"});
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private void addGif(String[] name) throws IOException
    {
        DefaultTableModel tableModel = (DefaultTableModel)_table.getModel();
        ImageDisplayOutputStream imageDisplayOutputStream = new ImageDisplayOutputStream(_table);

        assertEquals("Wrong number of rows", 0, tableModel.getRowCount());

        for(int n = 0; n < name.length; n++)
        {
            FileInputStream fis = new FileInputStream(name[n]);
            int data;


            imageDisplayOutputStream.startData();

            while ((data = fis.read()) != -1)
                imageDisplayOutputStream.write((byte)data);

            imageDisplayOutputStream.endData();
        }

        assertEquals("Wrong number of rows", name.length, tableModel.getRowCount());

        while(_table.getRowCount() != 0)
        {
            tableModel.removeRow(0);
        }
    }


    protected void tearDown() throws Exception
    {
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite();
        suite.addTest(new ImageDisplayOutputStreamTest("testSmallGif"));
        suite.addTest(new ImageDisplayOutputStreamTest("testLargeGif"));
        suite.addTest(new ImageDisplayOutputStreamTest("testMultipleGifs"));
        return suite;
    }

}
