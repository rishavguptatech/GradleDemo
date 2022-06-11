/*
 * HttpProxyUI.java
 *
 * Created on 07 September 2001, 10:17
 */

package com.mantiso.kevinj.http.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/** This class is the base window which will create other
 * windows to display and manage the HTTP traffic
 *
 * @author kevinj
 */
public class HttpProxyUI extends JFrame
{
    ProxyPanel proxyPanel;
    /** Creates new form HttpProxyUI
     * @param listenPort Port _server part of proxy will listen on
     * @param sendPort Port client part of proxy will send to
     * @param server Server that the proxy will connect to
     */
    public HttpProxyUI(int listenPort, int sendPort, String server)
    {
        try
        {
            initialiseContentTabbedPane();

            JPanel jpanel = createAdminPanel();
            addDisplayPanel("Admin", jpanel);


            setBounds(20, 20, 700, 800);
            setTitle("HttpProxy");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            addWindowListener(new WindowAdapter()
            {
                public void windowClosing(WindowEvent evt)
                {
                    exitForm(evt);
                }
            });

            if(listenPort != 0)
                addProxyPanel(listenPort, sendPort, server);

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private void addProxyPanel(int listenPort, int sendPort, String serverName)
    {
        JPanel jpanel;
        proxyPanel = new ProxyPanel(listenPort, sendPort, serverName);
        jpanel = proxyPanel.addProxyPanel();
        addDisplayPanel("Port " + Integer.toString(listenPort), jpanel);
        proxyPanel.startProxy();
    }

    private void initialiseContentTabbedPane()
    {
        contentTabbedPane = new JTabbedPane();
        contentTabbedPane.setFont(displayFont);
        getContentPane().add(contentTabbedPane, BorderLayout.CENTER);
    }

    private JPanel createAdminPanel()
    {
        JPanel adminPanel = new JPanel();
        JButton addButton;
        JPanel commandPanel;
        JLabel jLabel1;
        JLabel listenPortLabel;
        JLabel targetHostLabel;
        JLabel targetPortLabel;
        final JTextField targetHost;
        final JTextField targetPort;
        final JTextField listenPort;
        JPanel listenPortPanel;
        JPanel centerPanel;
        JPanel targetHostPanel;
        JPanel targetPortPanel;

        centerPanel = new JPanel();
        jLabel1 = new JLabel();

        listenPortPanel = new JPanel();
        listenPortLabel = new JLabel();
        listenPort = new JTextField();

        targetHostPanel = new JPanel();
        targetHostLabel = new JLabel();
        targetHost = new JTextField();
        targetPortPanel = new JPanel();
        targetPortLabel = new JLabel();
        targetPort = new JTextField();

        commandPanel = new JPanel();
        addButton = new JButton();

        adminPanel.setLayout(new OverlayLayout(adminPanel));

        centerPanel.setLayout(new GridLayout(5, 1));
        centerPanel.setMaximumSize(new Dimension(300, 120));
        centerPanel.setMinimumSize(new Dimension(300, 120));
        centerPanel.setPreferredSize(new Dimension(300, 120));

        jLabel1.setText("Create A New TCP Monitor");
        centerPanel.add(jLabel1);

        listenPortPanel.setLayout(new BorderLayout());

        listenPortPanel.setBorder(new EmptyBorder(new Insets(1, 1, 1, 150)));
        listenPortLabel.setText("Listen Port #");
        listenPortLabel.setPreferredSize(new Dimension(100, 16));
        listenPortLabel.setMinimumSize(new Dimension(100, 16));
        listenPortPanel.add(listenPortLabel, BorderLayout.WEST);

        listenPort.setPreferredSize(new Dimension(20, 16));
        listenPort.setMinimumSize(new Dimension(20, 16));
        listenPort.setMaximumSize(new Dimension(20, 16));
        listenPort.setText("8888");
        listenPortPanel.add(listenPort, BorderLayout.CENTER);

        centerPanel.add(listenPortPanel);

        targetHostPanel.setLayout(new BorderLayout());

        targetHostLabel.setText("Target Hostname");
        targetHostLabel.setPreferredSize(new Dimension(100, 16));
        targetHostLabel.setMaximumSize(new Dimension(110, 16));
        targetHostLabel.setMinimumSize(new Dimension(100, 16));
        targetHostPanel.add(targetHostLabel, BorderLayout.WEST);

        targetHost.setPreferredSize(new Dimension(63, 10));
        targetHost.setMinimumSize(new Dimension(4, 10));
        targetHost.setMaximumSize(new Dimension(63, 10));
        targetHost.setText("localhost");

        targetHostPanel.add(targetHost, BorderLayout.CENTER);

        centerPanel.add(targetHostPanel);

        targetPortPanel.setLayout(new BorderLayout());

        targetPortLabel.setText("Target Port");
        targetPortLabel.setPreferredSize(new Dimension(100, 16));
        targetPortLabel.setMinimumSize(new Dimension(100, 16));
        targetPortPanel.add(targetPortLabel, BorderLayout.WEST);

        targetPort.setPreferredSize(new Dimension(63, 16));
        targetPort.setMinimumSize(new Dimension(4, 16));
        targetPort.setMaximumSize(new Dimension(4, 16));
        targetPort.setText("8080");

        targetPortPanel.add(targetPort, BorderLayout.CENTER);

        centerPanel.add(targetPortPanel);

        addButton.setText("Add");
        addButton.setMnemonic('A');
        addButton.setMaximumSize(new Dimension(60, 20));
        addButton.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e)
            {
                addProxyPanel(Integer.parseInt(listenPort.getText()), Integer.parseInt(targetPort.getText()), targetHost.getText());
            }

        });

        commandPanel.setLayout(new BoxLayout(commandPanel, BoxLayout.X_AXIS));

        commandPanel.add(addButton);

        centerPanel.add(commandPanel);

        adminPanel.add(centerPanel);

        return adminPanel;
    }

    private void addDisplayPanel(String title, JPanel panel)
    {
        contentTabbedPane.add(title, panel);
    }

    private void removeDisplayPanel(JPanel panel)
    {
        contentTabbedPane.remove(panel);
    }

    /** Exit the Application */
    private void exitForm(WindowEvent evt)
    {
        System.exit(0);
    }

    /** Main entry point of the application
     *
     * @param args the command line arguments
     */
    public static void main(String args[])
    {
        int listenPort = 0;
        int sendPort = 0;
        String sendHost = null;

        String[] lookAndFeelClasses =
                {
                    "com.sun.java.swing.plaf.windows.WindowsLookAndFeel",
                    "com.sun.java.swing.plaf.gtk.GTKLookAndFeel",
                    "plaf.metal.MetalLookAndFeel",
                    UIManager.getCrossPlatformLookAndFeelClassName(),
                };

        for (int i = 0; i < lookAndFeelClasses.length; i++)
        {
            try
            {
                UIManager.setLookAndFeel(lookAndFeelClasses[i]);
                break;
            }
            catch (Exception e)
            {
            }
        }

        if (args.length == 0)
        {
            listenPort = 0;
            sendPort = 0;
            sendHost = "";
        }
        else
        {
            listenPort = Integer.parseInt(args[0]);
            sendPort = Integer.parseInt(args[1]);
            sendHost = args[2];
        }
        new HttpProxyUI(listenPort, sendPort, sendHost).setVisible(true);
    }

    private Font displayFont = new Font("Helvetica", 0, 10);
    JTabbedPane contentTabbedPane;

}

