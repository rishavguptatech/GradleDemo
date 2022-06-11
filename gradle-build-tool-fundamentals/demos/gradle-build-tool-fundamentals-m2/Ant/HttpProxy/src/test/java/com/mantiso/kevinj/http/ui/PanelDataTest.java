/*
 * Created by IntelliJ IDEA.
 * User: Kevin Jones
 * Date: 15-Jul-2002
 * Time: 16:25:15
 * To change template for new class use 
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package com.mantiso.kevinj.http.ui;

import junit.framework.*;

import javax.swing.*;

public class PanelDataTest extends TestCase
{
    PanelData panelData = null;

    public PanelDataTest(String name)
    {
        super(name);
    }

    protected void setUp() throws Exception
    {
        panelData = new PanelData();
    }



    public void testAddRequestHeaderListeners()
    {
        TextDisplayOutputStream tdos1 = new TextDisplayOutputStream(new JTextArea());
        TextDisplayOutputStream tdos2 = new TextDisplayOutputStream(new JTextArea());
        TextDisplayOutputStream tdos3 = new TextDisplayOutputStream(new JTextArea());
        panelData.addRequestHeadersListener(tdos1);
        panelData.addRequestHeadersListener(tdos2);
        panelData.addRequestHeadersListener(tdos3);
        int i = 0;
        if(panelData.requestHeaderListeners.remove(tdos1))
            i++;
        if(panelData.requestHeaderListeners.remove(tdos2))
            i++;
        if(panelData.requestHeaderListeners.remove(tdos3))
            i++;
        assertTrue("Should be 3 RequestHeaderListeners", i == 3);
    }

    public void testAddResponseHeaderListeners()
    {
        TextDisplayOutputStream tdos1 = new TextDisplayOutputStream(new JTextArea());
        TextDisplayOutputStream tdos2 = new TextDisplayOutputStream(new JTextArea());
        TextDisplayOutputStream tdos3 = new TextDisplayOutputStream(new JTextArea());
        panelData.addResponseHeadersListener(tdos1);
        panelData.addResponseHeadersListener(tdos2);
        panelData.addResponseHeadersListener(tdos3);
        int i = 0;
        if(panelData.responseHeaderListeners.remove(tdos1))
            i++;
        if(panelData.responseHeaderListeners.remove(tdos2))
            i++;
        if(panelData.responseHeaderListeners.remove(tdos3))
            i++;
        assertEquals("ResponseHeaderListeners", 3, i);
    }

    public void testAddRequestListeners()
    {
        assertTrue("Number of mime types should be 0", panelData.registeredRequestListeners.size() == 0);
        panelData.addRequestListener("text", new DisplayOutputStream());
        panelData.addRequestListener("text", new DisplayOutputStream());
        panelData.addRequestListener("text", new DisplayOutputStream());
        assertTrue("Number of mime types should be 1", panelData.registeredRequestListeners.size() == 1);
        assertTrue("register listeners for 'text' should be 3", ((java.util.HashSet)panelData.registeredRequestListeners.get("text")).size() == 3);

        panelData.addRequestListener("*", new DisplayOutputStream());
        assertTrue("Number of mime types should be 2", panelData.registeredRequestListeners.size() == 2);
        assertTrue("register listeners for 'text' should be 3", ((java.util.HashSet)panelData.registeredRequestListeners.get("text")).size() == 3);
        assertTrue("register listeners for '*' should be 1", ((java.util.HashSet)panelData.registeredRequestListeners.get("*")).size() == 1);
    }

    public void testAddResponseListeners()
    {
        assertTrue("Number of mime types should be 0", panelData.registeredResponseListeners.size() == 0);
        panelData.addResponseListener("text", new DisplayOutputStream());
        panelData.addResponseListener("text", new DisplayOutputStream());
        panelData.addResponseListener("text", new DisplayOutputStream());
        panelData.addResponseListener("text", new DisplayOutputStream());
        assertTrue("Number of mime types should be 1", panelData.registeredResponseListeners.size() == 1);
        assertTrue("register listeners for 'text' should be 4", ((java.util.HashSet)panelData.registeredResponseListeners.get("text")).size() == 4);

        panelData.addResponseListener("*", new DisplayOutputStream());
        panelData.addResponseListener("*", new DisplayOutputStream());
        assertTrue("Number of mime types should be 2", panelData.registeredRequestListeners.size() == 2);
        assertTrue("register listeners for 'text' should be 4", ((java.util.HashSet)panelData.registeredResponseListeners.get("text")).size() == 4);
        assertTrue("register listeners for '*' should be 2", ((java.util.HashSet)panelData.registeredResponseListeners.get("*")).size() == 2);

        panelData.addResponseListener("image", new DisplayOutputStream());
        panelData.addResponseListener("image", new DisplayOutputStream());
        panelData.addResponseListener("image", new DisplayOutputStream());
        assertTrue("Number of mime types should be 3", panelData.registeredResponseListeners.size() == 3);
        assertTrue("register listeners for 'text' should be 4", ((java.util.HashSet)panelData.registeredResponseListeners.get("text")).size() == 4);
        assertTrue("register listeners for 'image' should be 3", ((java.util.HashSet)panelData.registeredResponseListeners.get("*")).size() == 3);
        assertTrue("register listeners for '*' should be 2", ((java.util.HashSet)panelData.registeredResponseListeners.get("*")).size() == 2);

    }

    protected void tearDown() throws Exception
    {
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite();
        suite.addTest(new PanelDataTest("testAddRequestHeaderListeners"));
        suite.addTest(new PanelDataTest("testAddResponseHeaderListeners"));
        suite.addTest(new PanelDataTest("testAddRequestListeners"));
        suite.addTest(new PanelDataTest("testAddRequestListeners"));
        return suite;
    }

}

