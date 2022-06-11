/*
 * Created by IntelliJ IDEA.
 * User: Kevin Jones
 * Date: 19-Jun-02
 * Time: 15:34:39
 * To change template for new class use 
 * Code Style | Class Templates options (Tools | IDE Options).
 */
package com.mantiso.kevinj.http.ui;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;

import java.awt.event.ActionEvent;

public class InitDialogTest extends TestCase
{
    private String _server = "localhost";
    private String _listenPort = "8080";
    private String _sendPort = "80";

    InitDialogTest(String name)
    {
        super(name);
    }

    protected void setUp() throws Exception
    {

    }

    public void testInitDialogOK()
    {
        InitDialog id = new InitDialog(null, "Testing", true);
        assertFalse("OK should be false", id.isOk());
        assertEquals("Server name incorrect", _server, id.getServer());
        assertEquals("Listen port incorrect", _listenPort, id.getListenPort());
        assertEquals("Send port incorrect", _sendPort, id.getSendPort());

        ActionEvent evt = new ActionEvent(this, 0, "");
        id.okButtonActionPerformed(evt);
        assertTrue("OK should be true", id.isOk());
    }

    public void testInitDialogCancel()
    {
        InitDialog id = new InitDialog(null, "Testing", true);
        assertFalse("OK should be false", id.isOk());
        assertEquals("Server name incorrect", id.getServer(), _server);
        assertEquals("Listen port incorrect", id.getListenPort(), _listenPort);
        assertEquals("Send port incorrect", id.getSendPort(), _sendPort);

        ActionEvent evt = new ActionEvent(this, 0, "");
        id.cancelButtonActionPerformed(evt);
        assertFalse("OK should be false", id.isOk());
    }

    protected void tearDown() throws Exception
    {

    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite();
        suite.addTest(new InitDialogTest("testInitDialogCancel"));
        suite.addTest(new InitDialogTest("testInitDialogOK"));
        return suite;
    }

}
