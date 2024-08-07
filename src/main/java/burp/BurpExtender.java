package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField, serverPortField;
    private JButton testConnectionButton, startButton, stopButton, addButton, deleteButton, saveConfigButton, exportConfigButton, importConfigButton;
    private JTable ruleTable;
    private DefaultTableModel model;
    private ExecutorService executorService;
    private boolean isRunning = false;
    private Socket forwardingSocket;
    private OutputStream forwardingStream;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("增强型日志记录和转发器");

        executorService = Executors.newCachedThreadPool();
        SwingUtilities.invokeLater(this::buildUI);
        callbacks.addSuiteTab(BurpExtender.this);
        callbacks.registerHttpListener(this);
    }

    private void buildUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        serverIpField = new JTextField(15);
        serverPortField = new JTextField(5);
        testConnectionButton = new JButton("测试连接");
        startButton = new JButton("开始连接");
        stopButton = new JButton("停止连接");
        addButton = new JButton("添加规则");
        deleteButton = new JButton("删除规则");
        saveConfigButton = new JButton("保存配置");
        exportConfigButton = new JButton("导出配置");
        importConfigButton = new JButton("导入配置");

        setupUIComponents(gbc);

        testConnectionButton.addActionListener(e -> testConnection());
        startButton.addActionListener(e -> startLogging());
        stopButton.addActionListener(e -> stopLogging());
        addButton.addActionListener(e -> addRule());
        deleteButton.addActionListener(e -> deleteRule());
        stopButton.setEnabled(false);

        String[] columnNames = {"序号", "过滤方法", "过滤规则", "规则状态", "规则备注"};
        model = new DefaultTableModel(columnNames, 0);
        ruleTable = new JTable(model);
        JScrollPane scrollPane = new JScrollPane(ruleTable);
        scrollPane.setPreferredSize(new Dimension(700, 150));

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 7;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        mainPanel.add(scrollPane, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(addButton);
        buttonPanel.add(deleteButton);
        buttonPanel.add(saveConfigButton);
        buttonPanel.add(exportConfigButton);
        buttonPanel.add(importConfigButton);

        gbc.gridy = 2;
        mainPanel.add(buttonPanel, gbc);
    }

    private void setupUIComponents(GridBagConstraints gbc) {
        JPanel topPanel = new JPanel(new FlowLayout());
        topPanel.add(new JLabel("转发服务器 IP:"));
        topPanel.add(serverIpField);
        topPanel.add(new JLabel("端口:"));
        topPanel.add(serverPortField);
        topPanel.add(testConnectionButton);
        topPanel.add(startButton);
        topPanel.add(stopButton);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 6;
        mainPanel.add(topPanel, gbc);
    }

    private void testConnection() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(serverIpField.getText(), Integer.parseInt(serverPortField.getText())), 5000);
            JOptionPane.showMessageDialog(mainPanel, "连接测试成功！");
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel, "连接测试失败：" + e.getMessage());
        }
    }

    private void startLogging() {
        try {
            forwardingSocket = new Socket(serverIpField.getText(), Integer.parseInt(serverPortField.getText()));
            forwardingStream = forwardingSocket.getOutputStream();
            isRunning = true;
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(mainPanel, "无法连接到转发服务器: " + e.getMessage());
        }
    }

    private void stopLogging() {
        try {
            if (forwardingStream != null) {
                forwardingStream.close();
            }
            if (forwardingSocket != null) {
                forwardingSocket.close();
            }
        } catch (IOException e) {
            JOptionPane.showMessageDialog(mainPanel, "关闭连接时出错: " + e.getMessage());
        } finally {
            isRunning = false;
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
        }
    }

    private void addRule() {
        model.addRow(new Object[]{model.getRowCount() + 1, "", "", "Open", ""});
    }

    private void deleteRule() {
        int selectedRow = ruleTable.getSelectedRow();
        if (selectedRow != -1) {
            model.removeRow(selectedRow);
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isRunning) return;

        executorService.submit(() -> {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo.getRequest());
                IResponseInfo responseInfo = messageIsRequest ? null : helpers.analyzeResponse(messageInfo.getResponse());
                byte[] message = messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse();

                for (int i = 0; i < model.getRowCount(); i++) {
                    String method = (String) model.getValueAt(i, 1);
                    String rule = (String) model.getValueAt(i, 2);
                    String state = (String) model.getValueAt(i, 3);

                    if ("Open".equals(state) && requestInfo.getMethod().equalsIgnoreCase(method) && requestInfo.getUrl().toString().contains(rule)) {
                        // If matched, skip logging and forwarding
                        return;
                    }
                }

                // Log and forward if no rules were matched
                logRequestResponse(toolFlag, messageInfo, requestInfo, messageIsRequest);
                if (forwardingStream != null) {
                    forwardingStream.write(message);
                    forwardingStream.flush();
                }
            } catch (Exception e) {
                callbacks.printError("Error processing HTTP message: " + e.getMessage());
            }
        });
    }

    private void logRequestResponse(int toolFlag, IHttpRequestResponse messageInfo, IRequestInfo requestInfo, boolean isRequest) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String logEntry = String.format("[%s] [%s] %s %s\n", sdf.format(new Date()), callbacks.getToolName(toolFlag), requestInfo.getMethod(), requestInfo.getUrl().toString());
        callbacks.printOutput(logEntry);
    }

    @Override
    public String getTabCaption() {
        return "日志记录和转发";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
