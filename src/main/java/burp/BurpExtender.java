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

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JButton applyButton;
    private JButton stopButton;
    private JButton testConnectionButton;
    private JButton exportConfigButton;
    private JButton importConfigButton;
    private JTable ruleTable;
    private DefaultTableModel ruleTableModel;
    private Properties config;
    private boolean isRunning = false;
    private ExecutorService executorService;
    private PrintWriter logWriter;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Improved HTTP Logger");

        SwingUtilities.invokeLater(this::initializeUI);

        executorService = Executors.newFixedThreadPool(10);
        config = new Properties();
        loadConfig();

        callbacks.registerHttpListener(this);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        addServerSettings(gbc);
        addRuleTable(gbc);
        addButtons(gbc);

        callbacks.addSuiteTab(this);
    }

    private void addServerSettings(GridBagConstraints gbc) {
        gbc.gridx = 0;
        gbc.gridy = 0;
        mainPanel.add(new JLabel("转发服务器 IP:"), gbc);

        gbc.gridx = 1;
        serverIpField = new JTextField(15);
        serverIpField.setText(config.getProperty("forwardingIp", ""));
        mainPanel.add(serverIpField, gbc);

        gbc.gridx = 2;
        mainPanel.add(new JLabel("端口:"), gbc);

        gbc.gridx = 3;
        serverPortField = new JTextField(5);
        serverPortField.setText(config.getProperty("forwardingPort", ""));
        mainPanel.add(serverPortField, gbc);
    }

    private void addRuleTable(GridBagConstraints gbc) {
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.BOTH;
        
        String[] columnNames = {"序号", "过滤方法", "规则", "状态", "备注"};
        ruleTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 3) return Boolean.class;
                return super.getColumnClass(column);
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column != 0;
            }
        };
        ruleTable = new JTable(ruleTableModel);
        JScrollPane scrollPane = new JScrollPane(ruleTable);
        scrollPane.setPreferredSize(new Dimension(800, 300));
        mainPanel.add(scrollPane, gbc);

        JButton addRuleButton = new JButton("添加规则");
        addRuleButton.addActionListener(e -> addNewRule());
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.NONE;
        mainPanel.add(addRuleButton, gbc);

        JButton deleteRuleButton = new JButton("删除规则");
        deleteRuleButton.addActionListener(e -> deleteSelectedRule());
        gbc.gridx = 1;
        mainPanel.add(deleteRuleButton, gbc);
    }

    private void addButtons(GridBagConstraints gbc) {
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        applyButton = new JButton("开始记录");
        mainPanel.add(applyButton, gbc);

        gbc.gridx = 1;
        stopButton = new JButton("停止记录");
        stopButton.setEnabled(false);
        mainPanel.add(stopButton, gbc);

        gbc.gridx = 2;
        testConnectionButton = new JButton("测试连接");
        mainPanel.add(testConnectionButton, gbc);

        gbc.gridx = 0;
        gbc.gridy = 4;
        exportConfigButton = new JButton("导出配置");
        mainPanel.add(exportConfigButton, gbc);

        gbc.gridx = 1;
        importConfigButton = new JButton("导入配置");
        mainPanel.add(importConfigButton, gbc);

        applyButton.addActionListener(e -> startLogging());
        stopButton.addActionListener(e -> stopLogging());
        testConnectionButton.addActionListener(e -> testConnection());
        exportConfigButton.addActionListener(e -> exportConfig());
        importConfigButton.addActionListener(e -> importConfig());
    }

    private void addNewRule() {
        String[] filterMethods = {"黑名单扩展名", "域名过滤", "HTTP方法过滤", "状态码过滤", "IP过滤"};
        String filterMethod = (String) JOptionPane.showInputDialog(mainPanel, 
            "选择过滤方法:", "添加新规则", JOptionPane.QUESTION_MESSAGE, null, 
            filterMethods, filterMethods[0]);
        
        if (filterMethod != null) {
            String rule = JOptionPane.showInputDialog(mainPanel, "输入规则:");
            if (rule != null) {
                int rowCount = ruleTableModel.getRowCount();
                ruleTableModel.addRow(new Object[]{rowCount + 1, filterMethod, rule, true, ""});
            }
        }
    }

    private void deleteSelectedRule() {
        int selectedRow = ruleTable.getSelectedRow();
        if (selectedRow != -1) {
            ruleTableModel.removeRow(selectedRow);
            updateRuleNumbers();
        } else {
            JOptionPane.showMessageDialog(mainPanel, "请选择要删除的规则。", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateRuleNumbers() {
        for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
            ruleTableModel.setValueAt(i + 1, i, 0);
        }
    }

    private void startLogging() {
        String serverIp = serverIpField.getText().trim();
        String serverPort = serverPortField.getText().trim();

        if (serverIp.isEmpty() || serverPort.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        config.setProperty("forwardingIp", serverIp);
        config.setProperty("forwardingPort", serverPort);

        try {
            logWriter = new PrintWriter(new FileWriter("http_log.txt", true), true);
            isRunning = true;
            applyButton.setEnabled(false);
            stopButton.setEnabled(true);
            JOptionPane.showMessageDialog(mainPanel, "日志记录已启动。", "信息", JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(mainPanel, "启动日志记录时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopLogging() {
        isRunning = false;
        if (logWriter != null) {
            logWriter.close();
        }
        applyButton.setEnabled(true);
        stopButton.setEnabled(false);
        JOptionPane.showMessageDialog(mainPanel, "日志记录已停止。", "信息", JOptionPane.INFORMATION_MESSAGE);
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
            JOptionPane.showMessageDialog(mainPanel, "连接成功！", "信息", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainPanel, "连接失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
        }
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
        return "HTTP Logger";
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

                // 记录日志
                StringBuilder logEntry = new StringBuilder();
                logEntry.append("URL: ").append(url).append("\n");
                logEntry.append("Method: ").append(requestInfo.getMethod()).append("\n");
                logEntry.append("Protocol: ").append(requestInfo.getUrl().getProtocol()).append("\n");
                logEntry.append("Host: ").append(requestInfo.getUrl().getHost()).append("\n");
                
                if (!messageIsRequest) {
                    logEntry.append("Status Code: ").append(responseInfo.getStatusCode()).append("\n");
                }
                
                logEntry.append("Headers:\n");
                for (String header : requestInfo.getHeaders()) {
                    logEntry.append(header).append("\n");
                }
                
                logEntry.append("\n");
                logWriter.println(logEntry.toString());
                logWriter.flush();

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
}
