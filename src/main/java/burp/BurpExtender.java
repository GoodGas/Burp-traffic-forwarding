package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension, ProxyHistoryFilter {
    private MontoyaApi api;
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
    private final Set<Integer> filteredRequests = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final byte[] MESSAGE_SEPARATOR = "\r\n====================================================\r\n".getBytes();
    private static final String REQUEST_PREFIX = "REQUEST:";
    private static final String RESPONSE_PREFIX = "RESPONSE:";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("HTTP Forwarder");

        configManager = new ConfigManager(api);
        configManager.loadConfig();

        SwingUtilities.invokeLater(this::initializeUI);

        executorService = Executors.newCachedThreadPool();

        api.proxy().registerRequestHandler(this::processRequest);
        api.proxy().registerResponseHandler(this::processResponse);

        new Thread(this::handleResponses).start();
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
                return column == 2 || column == 3 || column == 4;
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

        ruleTableModel.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                configManager.saveConfig();
            }
        });

        loadSavedRules();

        api.userInterface().registerSuiteTab("HTTP Forwarder", mainPanel);
    }

    private void loadSavedRules() {
        int ruleCount = Integer.parseInt(configManager.getProperty("ruleCount", "0"));
        for (int i = 0; i < ruleCount; i++) {
            String method = configManager.getProperty("rule_" + i + "_method", "");
            String rule = configManager.getProperty("rule_" + i + "_rule", "");
            boolean status = Boolean.parseBoolean(configManager.getProperty("rule_" + i + "_status", "true"));
            String note = configManager.getProperty("rule_" + i + "_note", "");
            ruleTableModel.addRow(new Object[]{i + 1, method, rule, status, note});
        }
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
        String[] filterMethods = {"文件名过滤", "域名过滤", "HTTP方法过滤", "状态码过滤", "IP过滤"};
        String filterMethod = (String) JOptionPane.showInputDialog(mainPanel, 
            "选择过滤方法:", "添加新规则", JOptionPane.QUESTION_MESSAGE, null, 
            filterMethods, filterMethods[0]);
        
        if (filterMethod != null) {
            String rule = "";
            switch (filterMethod) {
                case "文件名过滤":
                    rule = JOptionPane.showInputDialog(mainPanel, "输入文件扩展名 (如 .jpg, .png):");
                    break;
                case "域名过滤":
                    rule = JOptionPane.showInputDialog(mainPanel, "输入域名正则表达式:");
                    break;
                case "HTTP方法过滤":
                    String[] methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"};
                    rule = (String) JOptionPane.showInputDialog(mainPanel, "选择HTTP方法:", "HTTP方法", JOptionPane.QUESTION_MESSAGE, null, methods, methods[0]);
                    break;
                case "状态码过滤":
                    rule = JOptionPane.showInputDialog(mainPanel, "输入状态码 (如 200, 404):");
                    break;
                case "IP过滤":
                    rule = JOptionPane.showInputDialog(mainPanel, "输入IP地址:");
                    break;
            }
            if (rule != null && !rule.isEmpty()) {
                int newRowIndex = ruleTableModel.getRowCount() + 1;
                ruleTableModel.addRow(new Object[]{newRowIndex, filterMethod, rule, true, ""});
                configManager.saveConfig();
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
            configManager.saveConfig();
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

    private void processRequest(ProxyHttpRequestResponse requestResponse) {
        if (!isRunning || persistentSocket == null || persistentSocket.isClosed()) return;

        executorService.submit(() -> {
            try {
                HttpRequestResponse httpRequestResponse = requestResponse.finalRequestResponse();
                ByteArray requestBytes = httpRequestResponse.request().toByteArray();
                String url = httpRequestResponse.url();
                String method = httpRequestResponse.request().method();
                String host = httpRequestResponse.request().httpService().host();

                boolean shouldFilter = false;
                for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                    String filterMethod = (String) ruleTableModel.getValueAt(i, 1);
                    String rule = (String) ruleTableModel.getValueAt(i, 2);
                    boolean isActive = (Boolean) ruleTableModel.getValueAt(i, 3);

                    if (!isActive) continue;

                    switch (filterMethod) {
                        case "文件名过滤":
                            if (url.toLowerCase().endsWith(rule.trim().toLowerCase())) {
                                shouldFilter = true;
                            }
                            break;
                        case "域名过滤":
                            if (Pattern.matches(rule, host)) {
                                shouldFilter = true;
                            }
                            break;
                        case "HTTP方法过滤":
                            if (method.equalsIgnoreCase(rule.trim())) {
                                shouldFilter = true;
                            }
                            break;
                        case "IP过滤":
                            try {
                                String ip = InetAddress.getByName(host).getHostAddress();
                                if (ip.equals(rule.trim())) {
                                    shouldFilter = true;
                                }
                            } catch (UnknownHostException e) {
                                logger.log(Level.WARNING, "无法解析主机名: " + host, e);
                            }
                            break;
                    }

                    if (shouldFilter) break;
                }

                int messageId = messageCounter.getAndIncrement();

                if (shouldFilter) {
                    filteredRequests.add(messageId);
                    return;
                }

                CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();
                responseMap.put(messageId, responseFuture);

                byte[] requestData = requestBytes.getBytes();
                byte[] idBytes = ByteBuffer.allocate(4).putInt(messageId).array();

                synchronized (persistentOutputStream) {
                    persistentOutputStream.write((REQUEST_PREFIX + messageId + "\n").getBytes());
                    persistentOutputStream.write(idBytes);
                    persistentOutputStream.write(requestData);
                    persistentOutputStream.write(MESSAGE_SEPARATOR);
                    persistentOutputStream.flush();
                }

                try {
                    byte[] responseData = responseFuture.get(30, TimeUnit.SECONDS);
                    requestResponse.setResponse(ByteArray.byteArray(responseData));
                } catch (InterruptedException | ExecutionException | TimeoutException e) {
                    logger.log(Level.WARNING, "等待响应时出错", e);
                } finally {
                    responseMap.remove(messageId);
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "处理请求时出错", e);
            }
        });
    }

    private void processResponse(ProxyHttpRequestResponse requestResponse) {
        if (!isRunning || persistentSocket == null || persistentSocket.isClosed()) return;

        executorService.submit(() -> {
            try {
                HttpRequestResponse httpRequestResponse = requestResponse.finalRequestResponse();
                ByteArray responseBytes = httpRequestResponse.response().toByteArray();
                int statusCode = httpRequestResponse.response().statusCode();

                int messageId = messageCounter.get() - 1; // 获取最后一个请求的ID

                if (filteredRequests.remove(messageId)) {
                    return;
                }

                boolean shouldFilter = false;
                for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                    String filterMethod = (String) ruleTableModel.getValueAt(i, 1);
                    String rule = (String) ruleTableModel.getValueAt(i, 2);
                    boolean isActive = (Boolean) ruleTableModel.getValueAt(i, 3);

                    if (!isActive) continue;

                    if (filterMethod.equals("状态码过滤") && String.valueOf(statusCode).equals(rule.trim())) {
                        shouldFilter = true;
                        break;
                    }
                }

                if (shouldFilter) {
                    return;
                }

                byte[] responseData = responseBytes.getBytes();
                byte[] idBytes = ByteBuffer.allocate(4).putInt(messageId).array();

                synchronized (persistentOutputStream) {
                    persistentOutputStream.write((RESPONSE_PREFIX + messageId + "\n").getBytes());
                    persistentOutputStream.write(idBytes);
                    persistentOutputStream.write(responseData);
                    persistentOutputStream.write(MESSAGE_SEPARATOR);
                    persistentOutputStream.flush();
                }

                CompletableFuture<byte[]> responseFuture = responseMap.get(messageId);
                if (responseFuture != null) {
                    responseFuture.complete(responseData);
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "处理响应时出错", e);
            }
        });
    }

    private void handleResponses() {
        while (isRunning) {
            try {
                String prefix = readLine(persistentInputStream);
                if (prefix == null) continue;

                int messageId;
                if (prefix.startsWith(REQUEST_PREFIX)) {
                    messageId = Integer.parseInt(prefix.substring(REQUEST_PREFIX.length()));
                } else if (prefix.startsWith(RESPONSE_PREFIX)) {
                    messageId = Integer.parseInt(prefix.substring(RESPONSE_PREFIX.length()));
                } else {
                    continue;
                }

                byte[] idBytes = new byte[4];
                int bytesRead = persistentInputStream.read(idBytes);
                if (bytesRead != 4) {
                    continue;
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                while ((bytesRead = persistentInputStream.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                    if (endsWith(baos.toByteArray(), MESSAGE_SEPARATOR)) {
                        break;
                    }
                }

                byte[] data = Arrays.copyOf(baos.toByteArray(), baos.size() - MESSAGE_SEPARATOR.length);

                if (prefix.startsWith(RESPONSE_PREFIX)) {
                    CompletableFuture<byte[]> responseFuture = responseMap.get(messageId);
                    if (responseFuture != null) {
                        responseFuture.complete(data);
                    } else {
                        logger.warning("收到未匹配的响应，消息ID: " + messageId);
                    }
                } else {
                    logger.info("收到请求，消息ID: " + messageId);
                }
            } catch (IOException e) {
                if (isRunning) {
                    logger.log(Level.SEVERE, "处理响应时出错", e);
                }
            }
        }
    }

    private String readLine(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = is.read()) != -1) {
            if (c == '\n') {
                break;
            }
            sb.append((char) c);
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    private boolean endsWith(byte[] array, byte[] suffix) {
        if (array.length < suffix.length) {
            return false;
        }
        for (int i = 0; i < suffix.length; i++) {
            if (array[array.length - suffix.length + i] != suffix[i]) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean matches(ProxyHttpRequestResponse requestResponse) {
        // 实现 ProxyHistoryFilter 接口的 matches 方法
        // 这里可以根据需要进行匹配，例如根据 URL、方法等
        // 这里简单地匹配所有请求
        return true;
    }

    private class ConfigManager {
        private Properties config = new Properties();
        private File configFile;

        public ConfigManager(MontoyaApi api) {
            String extensionFilePath = api.extension().filename();
            File extensionFile = new File(extensionFilePath);
            configFile = new File(extensionFile.getParentFile(), "http_forwarder_config.properties");
        }

        public void loadConfig() {
            if (!configFile.exists()) {
                try {
                    configFile.createNewFile();
                    logger.info("Created new configuration file: " + configFile.getAbsolutePath());
                } catch (IOException e) {
                    logger.log(Level.SEVERE, "无法创建配置文件", e);
                    return;
                }
            }

            try (InputStream input = new FileInputStream(configFile)) {
                config.load(input);
                logger.info("Loaded configuration from: " + configFile.getAbsolutePath());
            } catch (IOException ex) {
                logger.log(Level.WARNING, "加载配置文件时出错", ex);
            }
        }

        public void saveConfig() {
            String serverIp = serverIpField.getText().trim();
            String serverPort = serverPortField.getText().trim();

            setProperty("forwardingIp", serverIp);
            setProperty("forwardingPort", serverPort);

            setProperty("ruleCount", String.valueOf(ruleTableModel.getRowCount()));
            for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                setProperty("rule_" + i + "_method", (String) ruleTableModel.getValueAt(i, 1));
                setProperty("rule_" + i + "_rule", (String) ruleTableModel.getValueAt(i, 2));
                setProperty("rule_" + i + "_status", String.valueOf(ruleTableModel.getValueAt(i, 3)));
                setProperty("rule_" + i + "_note", (String) ruleTableModel.getValueAt(i, 4));
            }

            try (OutputStream output = new FileOutputStream(configFile)) {
                config.store(output, null);
                logger.info("Saved configuration to: " + configFile.getAbsolutePath());
            } catch (IOException io) {
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
                    loadSavedRules();

                    JOptionPane.showMessageDialog(mainPanel, "配置已成功导入。", "信息", JOptionPane.INFORMATION_MESSAGE);
                    saveConfig();
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
