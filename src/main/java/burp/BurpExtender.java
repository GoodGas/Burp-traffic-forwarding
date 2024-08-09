package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JButton testConnectionButton;
    private JButton startButton;
    private JButton stopButton;
    private JButton saveConfigButton;
    private JButton exportConfigButton;
    private JButton importConfigButton;
    private JTable ruleTable;
    private DefaultTableModel ruleTableModel;
    private Properties config;
    private boolean isRunning = false;
    private ExecutorService executorService;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("HTTP Forwarder");

        SwingUtilities.invokeLater(this::initializeUI);

        executorService = Executors.newFixedThreadPool(10);
        config = new Properties();
        loadConfig();

        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // First row
        gbc.gridx = 0;
        gbc.gridy = 0;
        mainPanel.add(new JLabel("转发服务器 IP:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        serverIpField = new JTextField(15);
        serverIpField.setText(config.getProperty("forwardingIp", ""));
        mainPanel.add(serverIpField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        mainPanel.add(new JLabel("端口:"), gbc);

        gbc.gridx = 3;
        gbc.weightx = 0.5;
        serverPortField = new JTextField(5);
        serverPortField.setText(config.getProperty("forwardingPort", ""));
        mainPanel.add(serverPortField, gbc);

        gbc.gridx = 4;
        gbc.weightx = 0;
        testConnectionButton = new JButton("测试连接");
        mainPanel.add(testConnectionButton, gbc);

        gbc.gridx = 5;
        startButton = new JButton("开始连接");
        mainPanel.add(startButton, gbc);

        gbc.gridx = 6;
        stopButton = new JButton("停止连接");
        stopButton.setEnabled(false);
        mainPanel.add(stopButton, gbc);

        // Second row
        gbc.gridx = 0;
        gbc.gridy = 1;
        JButton addRuleButton = new JButton("添加规则");
        mainPanel.add(addRuleButton, gbc);

        gbc.gridx = 1;
        JButton deleteRuleButton = new JButton("删除规则");
        mainPanel.add(deleteRuleButton, gbc);

        gbc.gridx = 2;
        saveConfigButton = new JButton("保存配置");
        mainPanel.add(saveConfigButton, gbc);

        gbc.gridx = 3;
        gbc.gridwidth = 2;
        exportConfigButton = new JButton("导出配置");
        mainPanel.add(exportConfigButton, gbc);

        gbc.gridx = 5;
        gbc.gridwidth = 2;
        importConfigButton = new JButton("导入配置");
        mainPanel.add(importConfigButton, gbc);

        // Rule table
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 7;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
      
        String[] columnNames = {"序号", "过滤方法", "过滤规则", "规则状态", "规则备注"};
        ruleTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 3) return Boolean.class;
                return super.getColumnClass(column);
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column != 0; // 序号列不可编辑
            }
        };
        ruleTable = new JTable(ruleTableModel);
        JScrollPane scrollPane = new JScrollPane(ruleTable);
        mainPanel.add(scrollPane, gbc);

        // Add action listeners
        testConnectionButton.addActionListener(e -> testConnection());
        startButton.addActionListener(e -> startForwarding());
        stopButton.addActionListener(e -> stopForwarding());
        addRuleButton.addActionListener(e -> addNewRule());
        deleteRuleButton.addActionListener(e -> deleteSelectedRule());
        saveConfigButton.addActionListener(e -> saveConfig());
        exportConfigButton.addActionListener(e -> exportConfig());
        importConfigButton.addActionListener(e -> importConfig());

        callbacks.addSuiteTab(this);
    }

    private void testConnection() {
        String serverIp = serverIpField.getText().trim();
        String serverPort = serverPortField.getText().trim();

        if (serverIp.isEmpty() || serverPort.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            Socket socket = new Socket(serverIp, Integer.parseInt(serverPort));
            socket.close();
            JOptionPane.showMessageDialog(mainPanel, "连接成功！", "测试结果", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel, "连接失败: " + e.getMessage(), "测试结果", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void addNewRule() {
        String[] filterMethods = {"黑名单扩展名", "域名过滤", "HTTP方法过滤", "状态码过滤", "IP过滤"};
        String filterMethod = (String) JOptionPane.showInputDialog(mainPanel, 
            "选择过滤方法:", "添加新规则", JOptionPane.QUESTION_MESSAGE, null, 
            filterMethods, filterMethods[0]);
      
        if (filterMethod != null) {
            String rule = JOptionPane.showInputDialog(mainPanel, "输入规则:");
            if (rule != null) {
                int newRowIndex = ruleTableModel.getRowCount() + 1;
                ruleTableModel.addRow(new Object[]{newRowIndex, filterMethod, rule, true, ""});
            }
        }
    }

    private void deleteSelectedRule() {
        int selectedRow = ruleTable.getSelectedRow();
        if (selectedRow != -1) {
            ruleTableModel.removeRow(selectedRow);
            // 重新编号
            for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                ruleTableModel.setValueAt(i + 1, i, 0);
            }
        } else {
            JOptionPane.showMessageDialog(mainPanel, "请选择要删除的规则。", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveConfig() {
        String serverIp = serverIpField.getText().trim();
        String serverPort = serverPortField.getText().trim();

        if (serverIp.isEmpty() || serverPort.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        config.setProperty("forwardingIp", serverIp);
        config.setProperty("forwardingPort", serverPort);

        config.setProperty("ruleCount", String.valueOf(ruleTableModel.getRowCount()));
        for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
            config.setProperty("rule_" + i + "_method", (String) ruleTableModel.getValueAt(i, 1));
            config.setProperty("rule_" + i + "_rule", (String) ruleTableModel.getValueAt(i, 2));
            config.setProperty("rule_" + i + "_status", String.valueOf(ruleTableModel.getValueAt(i, 3)));
            config.setProperty("rule_" + i + "_note", (String) ruleTableModel.getValueAt(i, 4));
        }

        try (OutputStream output = new FileOutputStream("config.properties")) {
            config.store(output, null);
            JOptionPane.showMessageDialog(mainPanel, "配置已保存并启用。", "信息", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException io) {
            JOptionPane.showMessageDialog(mainPanel, "保存配置时出错: " + io.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void startForwarding() {
        String serverIp = serverIpField.getText().trim();
        String serverPort = serverPortField.getText().trim();

        if (serverIp.isEmpty() || serverPort.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        config.setProperty("forwardingIp", serverIp);
        config.setProperty("forwardingPort", serverPort);

        isRunning = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        JOptionPane.showMessageDialog(mainPanel, "转发已启动。", "信息", JOptionPane.INFORMATION_MESSAGE);
    }

    private void stopForwarding() {
        isRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        JOptionPane.showMessageDialog(mainPanel, "转发已停止。", "信息", JOptionPane.INFORMATION_MESSAGE);
    }

    private void exportConfig() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                Properties exportConfig = new Properties();
                exportConfig.putAll(config);
                exportConfig.setProperty("ruleCount", String.valueOf(ruleTableModel.getRowCount()));
                for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                    exportConfig.setProperty("rule_" + i + "_method", (String) ruleTableModel.getValueAt(i, 1));
                    exportConfig.setProperty("rule_" + i + "_rule", (String) ruleTableModel.getValueAt(i, 2));
                    exportConfig.setProperty("rule_" + i + "_status", String.valueOf(ruleTableModel.getValueAt(i, 3)));
                    exportConfig.setProperty("rule_" + i + "_note", (String) ruleTableModel.getValueAt(i, 4));
                }
                oos.writeObject(exportConfig);
                JOptionPane.showMessageDialog(mainPanel, "配置已成功导出。", "信息", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出配置时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importConfig() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                Properties importedConfig = (Properties) ois.readObject();
                config.clear();
                config.putAll(importedConfig);
                serverIpField.setText(config.getProperty("forwardingIp", ""));
                serverPortField.setText(config.getProperty("forwardingPort", ""));

                ruleTableModel.setRowCount(0);
                int ruleCount = Integer.parseInt(config.getProperty("ruleCount", "0"));
                for (int i = 0; i < ruleCount; i++) {
                    String method = config.getProperty("rule_" + i + "_method");
                    String rule = config.getProperty("rule_" + i + "_rule");
                    boolean status = Boolean.parseBoolean(config.getProperty("rule_" + i + "_status"));
                    String note = config.getProperty("rule_" + i + "_note");
                    ruleTableModel.addRow(new Object[]{i + 1, method, rule, status, note});
                }

                JOptionPane.showMessageDialog(mainPanel, "配置已成功导入。", "信息", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException | ClassNotFoundException e) {
                JOptionPane.showMessageDialog(mainPanel, "导入配置时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void loadConfig() {
        try (InputStream input = new FileInputStream("config.properties")) {
            config.load(input);
        } catch (IOException ex) {
            callbacks.printError("加载配置文件时出错: " + ex.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return "HTTP Forwarder";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isRunning) return;

        executorService.submit(() -> {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                IResponseInfo responseInfo = messageIsRequest ? null : helpers.analyzeResponse(messageInfo.getResponse());
                String url = requestInfo.getUrl().toString().toLowerCase();
              
                // 应用过滤规则
                for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                    String filterMethod = (String) ruleTableModel.getValueAt(i, 1);
                    String rule = (String) ruleTableModel.getValueAt(i, 2);
                    boolean isActive = (Boolean) ruleTableModel.getValueAt(i, 3);
                  
                    if (!isActive) continue;
                  
                    switch (filterMethod) {
                        case "黑名单扩展名":
                            if (url.endsWith(rule.trim().toLowerCase())) return;
                            break;
                        case "域名过滤":
                            if (!url.matches(rule)) return;
                            break;
                        case "HTTP方法过滤":
                            if (!requestInfo.getMethod().equalsIgnoreCase(rule.trim())) return;
                            break;
                        case "状态码过滤":
                            if (!messageIsRequest && !String.valueOf(responseInfo.getStatusCode()).equals(rule.trim())) return;
                            break;
                        case "IP过滤":
                            if (!requestInfo.getUrl().getHost().equals(rule.trim())) return;
                            break;
                    }
                }

                // 转发请求
                String serverIp = config.getProperty("forwardingIp");
                int serverPort = Integer.parseInt(config.getProperty("forwardingPort"));
                forwardRequest(messageInfo, serverIp, serverPort);

            } catch (Exception e) {
                callbacks.printError("处理 HTTP 消息时出错: " + e.getMessage());
            }
        });
    }

    private void forwardRequest(IHttpRequestResponse messageInfo, String serverIp, int serverPort) {
        try (Socket socket = new Socket(serverIp, serverPort)) {
            OutputStream os = socket.getOutputStream();
            os.write(messageInfo.getRequest());
            os.flush();

            InputStream is = socket.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            messageInfo.setResponse(baos.toByteArray());
        } catch (IOException e) {
            callbacks.printError("转发请求时出错: " + e.getMessage());
        }
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
    }
}
