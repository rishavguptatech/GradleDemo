package com.mantiso.kevinj.http.ui;

import com.develop.io.MultiplexOutputStream;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Date;
import java.io.IOException;

import com.mantiso.kevinj.http.proxy.ConnectionData;
import com.mantiso.kevinj.http.proxy.ConnectionEvent;
import com.mantiso.kevinj.http.proxy.ConnectionListener;
import com.mantiso.kevinj.http.proxy.HttpProxy;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Created by IntelliJ IDEA.
 * User: kevinj
 * Date: 20-Oct-2003
 * Time: 16:12:42
 * To change this template use Options | File Templates.
 */
public class ProxyPanel implements ConnectionListener
{
    static Logger logger = LogManager.getLogger(ProxyPanel.class);
    HttpProxy httpProxy;
    JPanel displayPanel;
    JButton clearAll;
    private JButton clear;
    int listenPort;
    int sendPort;
    JTable table;
    ArrayList connectionEntries;
    String server;
    DefaultTableModel connectionTableModel;
    private JSplitPane mainSplitPane;
    private JLabel request;
    private JButton switchLayout;
    private JLabel response;
    private Font fixedFont = new Font("Courier New", 0, 12);
    private Font displayFont = new Font("Helvetica", 0, 10);
    private static final int STATE_COLUMN = 0;
    private static final int REQUEST_COLUMN = 4;


    public ProxyPanel(int listenPort, int sendPort, String server)
    {
        logger.debug("ProxyPanel: ctor");
        this.listenPort = listenPort;
        this.sendPort = sendPort;
        this.server = server;

        connectionEntries = new ArrayList();
    }

    public JPanel addProxyPanel()
    {
        displayPanel = new JPanel();
        displayPanel.setLayout(new BorderLayout());

        JPanel infoPanel;
        JPanel requestListPanel;

        initMainSplitPane();

        requestListPanel = createTablePanel();
        infoPanel = createInfoPanel();

        System.out.println("addProxyPanel");
//        initEmptyMainPanel();

        displayPanel.add(requestListPanel, BorderLayout.NORTH);
        displayPanel.add(mainSplitPane, BorderLayout.CENTER);
        displayPanel.add(infoPanel, BorderLayout.SOUTH);

        return displayPanel;
    }

    private PanelData addConnectionToPanel(String state, String date, String requestHost, String targetHost, String request)
    {
        PanelData panelData = createPanes();
        connectionTableModel.addRow(new String[]{state, date, requestHost, targetHost, request});
        logger.debug("addConnectioToPanel: rowCount: " + connectionTableModel.getRowCount());
        panelData.setConnectionId(connectionTableModel.getRowCount());
        return panelData;
    }

    private void addPanelsToSplitPane(JComponent requestPanel, JComponent responsePanel)
    {
        int loc = mainSplitPane.getLastDividerLocation();
        logger.debug("location is: " + loc);
        mainSplitPane.setLeftComponent(requestPanel);
        mainSplitPane.setRightComponent(responsePanel);
        if (loc != -1)
        {
            mainSplitPane.setDividerLocation(loc);
            mainSplitPane.setLastDividerLocation(loc);
        }
        else
        {
            mainSplitPane.setLastDividerLocation(250);
            mainSplitPane.setDividerLocation(250);
        }
    }

    private PanelData createPanes()
    {
        PanelData panelData = new PanelData();
        connectionEntries.add(panelData);
        addPanelsToSplitPane(panelData.getRequestPanel(), panelData.getResponsePanel());
        return panelData;
    }

    private JPanel createTablePanel()
    {
        JPanel tablePanel = new JPanel();
        tablePanel.setLayout(new BoxLayout(tablePanel, BoxLayout.Y_AXIS));
        tablePanel.setPreferredSize(new Dimension(100, 150));
        connectionTableModel = new DefaultTableModel(new String[]{"State", "Time", "Request Host", "Target Host", "Request"}, 0);
        connectionTableModel.addRow(new String[]{"-", "Most Recent", "---", "----", "-----"});

        table = new JTable();
        table.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        table.getSelectionModel().addListSelectionListener(new ListSelectionListener()
        {
            public void valueChanged(ListSelectionEvent e)
            {
                int currentSelection = table.getSelectionModel().getMaxSelectionIndex();
                logger.debug("currentSelection: " + currentSelection);

                if(currentSelection == -1)
                {
                    if(connectionEntries.size() == 0)
                    {
                        initEmptyMainPanel();
                        if(clear != null)
                            clear.setEnabled(false);
                        if(clearAll != null)
                            clearAll.setEnabled(false);
                    }
                    else
                    {
                        showPanel(0);
                        clear.setEnabled(true);
                    }
                }
                else
                {
                    showPanel(currentSelection);
                    clear.setEnabled(true);
                }
            }
        });

        table.setModel(connectionTableModel);

        setColumnWidths(table);

        JScrollPane tablePane = new JScrollPane(table);
        tablePanel.add(tablePane);

        JPanel commandPanel = new JPanel();

        commandPanel.setLayout(new BoxLayout(commandPanel, BoxLayout.X_AXIS));

        addClearButton(commandPanel);
        addClearAllButton(commandPanel);
        tablePanel.add(commandPanel);
        return tablePanel;
    }

    private void addClearButton(JPanel commandPanel)
    {
        clear = new JButton();
        clear.setEnabled(false);
        clear.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e)
            {
                int ndx = table.getSelectionModel().getMaxSelectionIndex();
                connectionEntries.remove(ndx - 1);
                connectionTableModel.removeRow(ndx);
            }

        });
        clear.setText("Clear");
        commandPanel.add(clear);
    }

    private void addClearAllButton(JPanel commandPanel)
    {
        clearAll = new JButton();
        clearAll.setEnabled(false);
        clearAll.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e)
            {
                clearAll.setEnabled(false);
                for(int i = connectionEntries.size(); i > 0 ; i--)
                {
                    connectionEntries.remove(i-1);
                    connectionTableModel.removeRow(i);
                }
                initEmptyMainPanel();
            }

        });
        clearAll.setText("Clear All");
        commandPanel.add(clearAll);
    }

    private void showPanel(int ndx)
    {
        PanelData panelData = null;

        if(connectionEntries.size() == 0)
            return;

        if (ndx == 0) // most recent
            panelData = (PanelData) connectionEntries.get(connectionEntries.size() - 1);
        else
            panelData = (PanelData) connectionEntries.get(ndx - 1);

        addPanelsToSplitPane(panelData.getRequestPanel(), panelData.getResponsePanel());
    }

    private void initEmptyMainPanel()
    {

        // create an empty textpane for north and south
        JTextArea textarea = new JTextArea();
        textarea.setEditable(false);
        textarea.setEnabled(false);
        textarea.setText("Connecting...");
        textarea.setMinimumSize(new Dimension(100, 250));
        System.out.println("mainsplitpane: " + mainSplitPane);

        mainSplitPane.setLeftComponent(textarea);
        textarea = new JTextArea();
        textarea.setEditable(false);
        mainSplitPane.setRightComponent(textarea);
//        mainSplitPane.setLastDividerLocation(250);
        mainSplitPane.validate();
        mainSplitPane.setDividerLocation(250);
        mainSplitPane.setLastDividerLocation(250);
        // readonly
        // with connecting... text
    }

    private void setColumnWidths(JTable table)
    {
        TableColumn col = table.getColumnModel().getColumn(STATE_COLUMN);
        col.setMaxWidth(col.getPreferredWidth() / 2);

        col = table.getColumnModel().getColumn(REQUEST_COLUMN);
        col.setPreferredWidth(col.getPreferredWidth() * 2);
    }

    private JPanel createInfoPanel()
    {
        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints1;

        request = new JLabel();
        switchLayout = new JButton();
        response = new JLabel();

        infoPanel.setPreferredSize(new Dimension(10, 30));
        request.setText("Request");
        request.setHorizontalAlignment(SwingConstants.LEFT);
        request.setHorizontalTextPosition(SwingConstants.LEFT);
        gridBagConstraints1 = new GridBagConstraints();
        gridBagConstraints1.gridwidth = 30;
        gridBagConstraints1.fill = GridBagConstraints.BOTH;
        gridBagConstraints1.anchor = GridBagConstraints.WEST;
        gridBagConstraints1.weightx = 0.3;
        infoPanel.add(request, gridBagConstraints1);

/*
        clear = new JButton();
        clear.setMnemonic('C');
        clear.setFont(displayFont);
        clear.setText("Clear");
        clear.setPreferredSize(new Dimension(20, 50));
        clear.setMaximumSize(new Dimension(80, 27));
        clear.setMinimumSize(new Dimension(70, 27));
        clear.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                ClearActionPerformed(evt);
            }
        });
*/

        switchLayout.setMnemonic('S');
        switchLayout.setFont(displayFont);
        switchLayout.setText("Switch Layout");
        switchLayout.setPreferredSize(new Dimension(120, 50));
        switchLayout.setMaximumSize(new Dimension(120, 27));
        switchLayout.setMinimumSize(new Dimension(120, 27));
        switchLayout.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent evt)
            {
                SwitchActionPerformed(evt);
            }
        });

        gridBagConstraints1 = new GridBagConstraints();
        gridBagConstraints1.fill = GridBagConstraints.BOTH;
//        infoPanel.add(clear, gridBagConstraints1);
        infoPanel.add(switchLayout, gridBagConstraints1);

        response.setText("Response");
        response.setHorizontalAlignment(SwingConstants.RIGHT);
        gridBagConstraints1 = new GridBagConstraints();
        gridBagConstraints1.fill = GridBagConstraints.BOTH;
        gridBagConstraints1.anchor = GridBagConstraints.EAST;
        gridBagConstraints1.weightx = 0.3;
        infoPanel.add(response, gridBagConstraints1);

        return infoPanel;
    }

    private void initMainSplitPane()
    {
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setDividerSize(2);
        mainSplitPane.setContinuousLayout(true);
        mainSplitPane.setOneTouchExpandable(true);
        mainSplitPane.setDividerLocation(0.5);
        System.out.println("mainSplitPane: " + mainSplitPane);
    }

/*
    private void ClearActionPerformed(ActionEvent evt)
    {
        int nCount = connectionTableModel.getRowCount();

        for (int i = 0; i < nCount; i++)
        {
            // first entry is 'last'
            connectionTableModel.removeRow(1);
            connectionEntries.remove(0);
            displayPanel.removeAll();
        }
    }
*/

    private void SwitchActionPerformed(ActionEvent evt)
    {
        if (mainSplitPane.getOrientation() == JSplitPane.VERTICAL_SPLIT)
            mainSplitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
        else
            mainSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
    }

    public void startProxy()
    {
        httpProxy = new HttpProxy(listenPort, sendPort, server);
        httpProxy.addConnectionListener(this);

        // create the output stream for the request _headers
        httpProxy.start();
    }

    public JPanel getDisplayPanel()
    {
        return displayPanel;
    }

    public int getListenPort()
    {
        return listenPort;
    }

    public void setListenPort(int listenPort)
    {
        this.listenPort = listenPort;
    }

    public int getSendPort()
    {
        return sendPort;
    }

    public String getServer()
    {
        return server;
    }

    public void addNewConnection(ConnectionEvent evt)
    {
        ConnectionData data = evt.getConnectionData();
        HttpProxy httpProxy = (HttpProxy) evt.getSource();
        logger.debug("addNewConnection: " + data);

        PanelData panelData = addConnectionToPanel(data.getState(),
                data.getDateStarted().toString(),
                data.getRequestHost(),
                data.getTargetHost(),
                data.getRequest());

        panelData.registerListeners();

        logger.debug("addNewConnection: connectionId" + panelData.getConnectionId());

        try
        {
            httpProxy.startProxies(data.getTargetHost(),
                    data.getListenPort(),
                    data.getServerSocket(),
                    panelData.getConnectionId(),
                    panelData.getRequestHeaderListeners(),
                    panelData.getRegisteredRequestListeners(),
                    panelData.getResponseHeaderListeners(),
                    panelData.getRegisteredResponseListeners());

            clearAll.setEnabled(true);
        }
        catch (IOException e)
        {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }
    }

    public void updateConnection(ConnectionEvent evt)
    {
        ConnectionData data = evt.getConnectionData();
        logger.debug("updateConnection: " + data);
        int ndx = data.getConnectionId() - 1;

        if (data.getState() != null && data.getState().equals("") == false)
            connectionTableModel.setValueAt(data.getState(), ndx, 0);
        if (data.getDateStarted() != null && data.getDateStarted().equals(new Date(0)) == false)
            connectionTableModel.setValueAt(data.getDateStarted().toString(), ndx, 2);
        if (data.getRequestHost() != null && data.getRequestHost().equals("") == false)
            connectionTableModel.setValueAt(data.getRequestHost(), ndx, 2);
        if (data.getTargetHost() != null && data.getTargetHost().equals("") == false)
            connectionTableModel.setValueAt(data.getTargetHost(), ndx, 3);
        if (data.getRequest() != null && data.getRequest().equals("") == false)
            connectionTableModel.setValueAt(data.getRequest(), ndx, 4);
    }

}


class PanelData
{
    private Font fixedFont = new Font("Courier New", 0, 12);
    private Font displayFont = new Font("Helvetica", 0, 10);

    int connectionId;

    HashMap registeredRequestListeners;
    HashMap registeredResponseListeners;
    MultiplexOutputStream requestHeaderListeners = null;
    MultiplexOutputStream responseHeaderListeners = null;

    JComponent requestPanel;
    JComponent responsePanel;
    private JTextArea responseHeaders = new JTextArea();
    private JTextArea fullResponse = new JTextArea();
    private JTextArea responseText = new JTextArea();
    private JTextArea responseHex = new JTextArea();
    private JTextArea responseHtml = new JTextArea();
    private JTable imagesResponse = new JTable();

    private JTextArea requestHeaders = new JTextArea();
    private JTextArea fullRequest = new JTextArea();
    private JTextArea requestText = new JTextArea();
    private JTextArea requestHex = new JTextArea();

    public PanelData()
    {
        createRequestPanel();
        createResponsePanel();
        requestHeaderListeners = new MultiplexOutputStream();
        responseHeaderListeners = new MultiplexOutputStream();

        registeredRequestListeners = new HashMap();
        registeredResponseListeners = new HashMap();
    }

    private void createResponsePanel()
    {
        responsePanel = new JPanel();
        JScrollPane responseHeadersPane = new JScrollPane();
        JScrollPane fullResponsePane = new JScrollPane();
        JPanel responseBodyPanel = new JPanel();
        JTabbedPane responseTabbedPane = new JTabbedPane();
        JScrollPane responseTextScrollPane = new JScrollPane();
        JScrollPane responseHexScrollPane = new JScrollPane();
        JScrollPane responseImageScrollPane = new JScrollPane();
        JScrollPane responseHtmlScrollPane = new JScrollPane();

        responsePanel.setLayout(new BorderLayout());

        fullResponsePane.setMinimumSize(new Dimension(22, 10));
        fullResponsePane.setViewportView(fullResponse);
        fullResponse.setEditable(false);
        fullResponse.setFont(fixedFont);

        responseTabbedPane.addTab("Full", fullResponsePane);

        responseHeadersPane.setMinimumSize(new Dimension(22, 10));
        responseHeadersPane.setViewportView(responseHeaders);
        responseHeaders.setEditable(false);
        responseHeaders.setFont(fixedFont);

        responseBodyPanel.setLayout(new BorderLayout());

        responseTabbedPane.addTab("Headers", responseHeadersPane);

        responseText.setEditable(false);
        responseText.setFont(fixedFont);
        responseTextScrollPane.setViewportView(responseText);

        responseTabbedPane.addTab("Text", responseTextScrollPane);

        responseHtml.setEditable(false);
        responseHtml.setFont(fixedFont);

        responseHtmlScrollPane.setViewportView(responseHex);

        responseTabbedPane.addTab("HTML", responseHtmlScrollPane);
        responseTabbedPane.setFont(displayFont);

        responseHex.setEditable(false);
        responseHex.setFont(fixedFont);

        responseHexScrollPane.setViewportView(responseHex);

        responseTabbedPane.addTab("Hex", responseHexScrollPane);
        responseTabbedPane.setFont(displayFont);

        responseImageScrollPane.setViewportView(imagesResponse);

        responseTabbedPane.addTab("Images", responseImageScrollPane);

        responseBodyPanel.add(responseTabbedPane, BorderLayout.CENTER);

        responsePanel.add(responseTabbedPane, BorderLayout.CENTER);

        imagesResponse.setModel(
                new DefaultTableModel(
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
                        ImageIcon.class
                    };
                    boolean[] canEdit = new boolean[]
                    {
                        false
                    };

                    public Class<?> getColumnClass(int columnIndex)
                    {
                        return types[columnIndex];
                    }

                    public boolean isCellEditable(int rowIndex, int columnIndex)
                    {
                        return canEdit[columnIndex];
                    }
                });

//        responseSplitPane.setDividerLocation(0.5);

    }

    private void createRequestPanel()
    {
        requestPanel = new JPanel();
        JPanel requestBodyPanel = new JPanel();
        JTabbedPane requestTabbedPane = new JTabbedPane();
        JScrollPane fullRequestPane = new JScrollPane();
        JScrollPane requestTextScrollPane = new JScrollPane();
        JScrollPane requestHexScrollPane = new JScrollPane();
        JScrollPane requestHeadersPane = new JScrollPane();

        requestPanel.setLayout(new BoxLayout(requestPanel, BoxLayout.Y_AXIS));

        fullRequestPane.setMinimumSize(new Dimension(22, 10));
        fullRequestPane.setViewportView(fullRequest);
        fullRequest.setEditable(false);
        fullRequest.setFont(fixedFont);

        requestTabbedPane.addTab("Full", fullRequestPane);

        requestHeadersPane.setViewportView(requestHeaders);
        requestHeaders.setEditable(false);
        requestHeaders.setFont(fixedFont);


        requestBodyPanel.setLayout(new BoxLayout(requestBodyPanel, BoxLayout.Y_AXIS));

        requestTabbedPane.addTab("Headers", requestHeadersPane);

        requestText.setEditable(false);
        requestText.setFont(fixedFont);
        requestTextScrollPane.setViewportView(requestText);

        requestTabbedPane.addTab("Text", requestTextScrollPane);

        requestHex.setEditable(false);
        requestHex.setFont(fixedFont);

        requestHexScrollPane.setViewportView(requestHex);

        requestTabbedPane.addTab("Hex", requestHexScrollPane);
        requestTabbedPane.setFont(displayFont);

        requestBodyPanel.add(requestTabbedPane);

        requestPanel.add(requestTabbedPane);
    }

    public JComponent getRequestPanel()
    {
        return requestPanel;
    }

    public JComponent getResponsePanel()
    {
        return responsePanel;
    }

    public JTextArea getResponseHeaders()
    {
        return responseHeaders;
    }

    public JTextArea getResponseText()
    {
        return responseText;
    }

    public JTextArea getResponseHex()
    {
        return responseHex;
    }

    public JTextArea getResponseHtml()
    {
        return responseHtml;
    }

    public JTable getImagesResponse()
    {
        return imagesResponse;
    }

    public JTextArea getRequestHeaders()
    {
        return requestHeaders;
    }

    public JTextArea getRequestText()
    {
        return requestText;
    }

    public JTextArea getRequestHex()
    {
        return requestHex;
    }

    public JTextArea getFullResponse()
    {
        return fullResponse;
    }

    public JTextArea getFullRequest()
    {
        return fullRequest;
    }

    public MultiplexOutputStream getRequestHeaderListeners()
    {
        return requestHeaderListeners;
    }

    public MultiplexOutputStream getResponseHeaderListeners()
    {
        return responseHeaderListeners;
    }

    public HashMap getRegisteredRequestListeners()
    {
        return registeredRequestListeners;
    }

    public HashMap getRegisteredResponseListeners()
    {
        return registeredResponseListeners;
    }

    public void addRequestHeadersListener(DisplayOutputStream os)
    {
        requestHeaderListeners.add(os);
    }

    public void addResponseHeadersListener(DisplayOutputStream os)
    {
        responseHeaderListeners.add(os);
    }

    public void addRequestListener(String majorMIMEType, DisplayOutputStream os)
    {
        registerListener(majorMIMEType, os, registeredRequestListeners);
    }

    public void addResponseListener(String majorMIMEType, DisplayOutputStream os)
    {
        registerListener(majorMIMEType, os, registeredResponseListeners);
    }


    void registerListener(String majorMIMEType, DisplayOutputStream os, HashMap registeredListeners)
    {
        java.util.HashSet displayOutputStreamSet = (java.util.HashSet) registeredListeners.get(majorMIMEType);
        if (displayOutputStreamSet == null)
        {
            displayOutputStreamSet = new java.util.HashSet();
            registeredListeners.put(majorMIMEType, displayOutputStreamSet);
        }
        displayOutputStreamSet.add(os);
    }

    public void registerListeners()
    {
        TextDisplayOutputStream requestHeaderListeners = new TextDisplayOutputStream(getRequestHeaders());
        TextDisplayOutputStream responseHeaderListeners = new TextDisplayOutputStream(getResponseHeaders());
        TextDisplayOutputStream applicationDataListener = new TextDisplayOutputStream(getRequestText());
        HexDisplayOutputStream hexRequestListener = new HexDisplayOutputStream(getRequestHex());
        TextDisplayOutputStream textResponseListener = new TextDisplayOutputStream(getResponseText());
        HexDisplayOutputStream hexResponseListener = new HexDisplayOutputStream(getResponseHex());
        //HtmlDisplayOutputStream htmlResponseListener = new HtmlDisplayOutputStream(getResponseHtml());
        ImageDisplayOutputStream imageListener = new ImageDisplayOutputStream(getImagesResponse());
        TextDisplayOutputStream fullResponseListeners = new TextDisplayOutputStream(getFullResponse());
        TextDisplayOutputStream fullRequestListeners = new TextDisplayOutputStream(getFullRequest());

        addRequestHeadersListener(requestHeaderListeners);
        addRequestHeadersListener(fullRequestListeners);
        addResponseHeadersListener(responseHeaderListeners);
        addResponseHeadersListener(fullResponseListeners);

        addRequestListener("*", hexRequestListener);
        addRequestListener("*", fullRequestListeners);
        addRequestListener("application", applicationDataListener);

        addResponseListener("text", textResponseListener);
        addResponseListener("*", hexResponseListener);
        //addResponseListener("text/html", htmlResponseListener);
        addResponseListener("*", fullResponseListeners);
        addResponseListener("image", imageListener);
    }

    public int getConnectionId()
    {
        return connectionId;
    }

    public void setConnectionId(int connectionId)
    {
        this.connectionId = connectionId;
    }
}