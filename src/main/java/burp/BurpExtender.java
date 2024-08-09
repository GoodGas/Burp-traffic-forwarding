package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    private ConfigManager configManager;
    private boolean isRunning = false;
    private ExecutorService executorService;
    private Socket persistentSocket;
    private OutputStream persistentOutputStream;
    private InputStream persistentInputStream;
    private static final Logger logger = Logger.getLogger(BurpExtender.class.getName());
    private final ConcurrentHashMap<Integer, CompletableFuture<byte[]>> responseMap = new ConcurrentHashMap<>();
    private final AtomicInteger messageCounter = new AtomicInteger(0);

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("HTTP Forwarder");

        SwingUtilities.invokeLater(this::initializeUI);

        executorService = Executors.newFixedThreadPool(10);
        configManager = new ConfigManager();
        configManager.loadConfig();

        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
    }

    private void initializeUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        mainPanel.add(new JLabel("转发服务器 IP:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        serverIpField = new JTextField(15);
        serverIpField.setText(configManager.getProperty("forwardingIp", ""));
        mainPanel.add(serverIpField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        mainPanel.add(new JLabel("端口:"), gbc);

        gbc.gridx = 3;
        gbc.weightx = 0.5;
        serverPortField = new JTextField(5);
        serverPortField.setText(configManager.getProperty("forwardingPort", ""));
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
                return column == 4;
            }
        };
        ruleTable = new JTable(ruleTableModel);

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        for (int i = 0; i < ruleTable.getColumnCount() - 1; i++) {
            ruleTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }

        JTableHeader header = ruleTable.getTableHeader();
        header.setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus,
                                                           int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value,
                        isSelected, hasFocus, row, column);
                label.setHorizontalAlignment(JLabel.CENTER);
                label.setFont(label.getFont().deriveFont(Font.BOLD));
                return label;
            }
        });

        JScrollPane scrollPane = new JScrollPane(ruleTable);
        mainPanel.add(scrollPane, gbc);

        testConnectionButton.addActionListener(e -> testConnection());
        startButton.addActionListener(e -> startForwarding());
        stopButton.addActionListener(e -> stopForwarding());
        addRuleButton.addActionListener(e -> addNewRule());
        deleteRuleButton.addActionListener(e -> deleteSelectedRule());
        saveConfigButton.addActionListener(e -> configManager.saveConfig());
        exportConfigButton.addActionListener(e -> configManager.exportConfig());
        importConfigButton.addActionListener(e -> configManager.importConfig());

        callbacks.addSuiteTab(this);
    }

    private void testConnection() {
        String serverIp = serverIpField.getText().trim();
        String serverPort = serverPortField.getText().trim();

        if (serverIp.isEmpty() || serverPort.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        CompletableFuture.runAsync(() -> {
            try (Socket socket = new Socket(serverIp, Integer.parseInt(serverPort))) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(mainPanel, "连接成功！", "测试结果", JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(mainPanel, "连接失败: " + e.getMessage(), "测试结果", JOptionPane.ERROR_MESSAGE));
                logger.log(Level.WARNING, "测试连接失败", e);
            }
        });
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
            for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                ruleTableModel.setValueAt(i + 1, i, 0);
            }
        } else {
            JOptionPane.showMessageDialog(mainPanel, "请选择要删除的规则。", "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void startForwarding() {
        String serverIp = serverIpField.getText().trim();
        String serverPort = serverPortField.getText().trim();

        if (serverIp.isEmpty() || serverPort.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        configManager.setProperty("forwardingIp", serverIp);
        configManager.setProperty("forwardingPort", serverPort);

        CompletableFuture.runAsync(() -> {
            try {
                persistentSocket = new Socket(serverIp, Integer.parseInt(serverPort));
                persistentOutputStream = persistentSocket.getOutputStream();
                persistentInputStream = persistentSocket.getInputStream();
                
                isRunning = true;
                SwingUtilities.invokeLater(() -> {
                    startButton.setEnabled(false);
                    stopButton.setEnabled(true);
                    JOptionPane.showMessageDialog(mainPanel, "转发已启动。", "信息", JOptionPane.INFORMATION_MESSAGE);
                });

                // 启动响应处理线程
                new Thread(this::handleResponses).start();
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(mainPanel, "启动转发时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE));
                logger.log(Level.SEVERE, "启动转发失败", e);
            }
        });
    }

    private void stopForwarding() {
        isRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        
        try {
            if (persistentSocket != null && !persistentSocket.isClosed()) {
                persistentSocket.close();
            }
            persistentOutputStream = null;
            persistentInputStream = null;
        } catch (IOException e) {
            logger.log(Level.WARNING, "关闭连接时出错", e);
        }
        
        JOptionPane.showMessageDialog(mainPanel, "转发已停止。", "信息", JOptionPane.INFORMATION_MESSAGE);
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
        if (!isRunning || persistentSocket == null || persistentSocket.isClosed()) return;

        executorService.submit(() -> {
            try {
                if (messageIsRequest) {
                    processRequest(messageInfo);
                } else {
                    processResponse(messageInfo);
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "处理 HTTP 消息时出错", e);
            }
        });
    }

    private void processRequest(IHttpRequestResponse messageInfo) throws IOException {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString().toLowerCase();

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
                case "IP过滤":
                    if (!requestInfo.getUrl().getHost().equals(rule.trim())) return;
                    break;
            }
        }

        int messageId = messageCounter.getAndIncrement();
        CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();
        responseMap.put(messageId, responseFuture);

        byte[] requestData = messageInfo.getRequest();
        byte[] idBytes = ByteBuffer.allocate(4).putInt(messageId).array();

        synchronized (persistentOutputStream) {
            persistentOutputStream.write(idBytes);
            persistentOutputStream.write(requestData);
            persistentOutputStream.flush();
        }

        try {
            byte[] responseData = responseFuture.get(30, TimeUnit.SECONDS);
            messageInfo.setResponse(responseData);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            logger.log(Level.WARNING, "等待响应时出错", e);
        } finally {
            responseMap.remove(messageId);
        }
    }

    private void processResponse(IHttpRequestResponse messageInfo) {
        // 这个方法不再需要，因为响应将在handleResponses方法中处理
    }

    private void handleResponses() {
        while (isRunning) {
            try {
                byte[] idBytes = new byte[4];
                int bytesRead = persistentInputStream.read(idBytes);
                if (bytesRead != 4) {
                    continue;
                }
                int messageId = ByteBuffer.wrap(idBytes).getInt();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                while ((bytesRead = persistentInputStream.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                    if (persistentInputStream.available() == 0) break;
                }

                byte[] responseData = baos.toByteArray();
                CompletableFuture<byte[]> responseFuture = responseMap.get(messageId);
                if (responseFuture != null) {
                    responseFuture.complete(responseData);
                }
            } catch (IOException e) {
                if (isRunning) {
                    logger.log(Level.SEVERE, "处理响应时出错", e);
                }
            }
        }
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
        stopForwarding();
    }

    private class ConfigManager {
        private Properties config = new Properties();

        public void loadConfig() {
            try (InputStream input = new FileInputStream("config.properties")) {
                config.load(input);
            } catch (IOException ex) {
                logger.log(Level.WARNING, "加载配置文件时出错", ex);
            }
        }

        public void saveConfig() {
            String serverIp = serverIpField.getText().trim();
            String serverPort = serverPortField.getText().trim();

            if (serverIp.isEmpty() || serverPort.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            setProperty("forwardingIp", serverIp);
            setProperty("forwardingPort", serverPort);

            setProperty("ruleCount", String.valueOf(ruleTableModel.getRowCount()));
            for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                setProperty("rule_" + i + "_method", (String) ruleTableModel.getValueAt(i, 1));
                setProperty("rule_" + i + "_rule", (String) ruleTableModel.getValueAt(i, 2));
                setProperty("rule_" + i + "_status", String.valueOf(ruleTableModel.getValueAt(i, 3)));
                setProperty("rule_" + i + "_note", (String) ruleTableModel.getValueAt(i, 4));
            }

            try (OutputStream output = new FileOutputStream("config.properties")) {
                config.store(output, null);
                JOptionPane.showMessageDialog(mainPanel, "配置已保存并启用。", "信息", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException io) {
                JOptionPane.showMessageDialog(mainPanel, "保存配置时出错: " + io.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                logger.log(Level.SEVERE, "保存配置失败", io);
            }
        }

        public void exportConfig() {
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
                    logger.log(Level.SEVERE, "导出配置失败", e);
                }
            }
        }

        public void importConfig() {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                    Properties importedConfig = (Properties) ois.readObject();
                    config.clear();
                    config.putAll(importedConfig);
                    serverIpField.setText(getProperty("forwardingIp", ""));
                    serverPortField.setText(getProperty("forwardingPort", ""));

                    ruleTableModel.setRowCount(0);
                    int ruleCount = Integer.parseInt(getProperty("ruleCount", "0"));
                    for (int i = 0; i < ruleCount; i++) {
                        String method = getProperty("rule_" + i + "_method", "");
                        String rule = getProperty("rule_" + i + "_rule", "");
                        boolean status = Boolean.parseBoolean(getProperty("rule_" + i + "_status", "true"));
                        String note = getProperty("rule_" + i + "_note", "");
                        ruleTableModel.addRow(new Object[]{i + 1, method, rule, status, note});
                    }

                    JOptionPane.showMessageDialog(mainPanel, "配置已成功导入。", "信息", JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException | ClassNotFoundException e) {
                    JOptionPane.showMessageDialog(mainPanel, "导入配置时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                    logger.log(Level.SEVERE, "导入配置失败", e);
                }
            }
        }

        public String getProperty(String key, String defaultValue) {
            return config.getProperty(key, defaultValue);
        }

        public String getProperty(String key) {
            return config.getProperty(key);
        }

        public void setProperty(String key, String value) {
            config.setProperty(key, value);
        }
    }
}
