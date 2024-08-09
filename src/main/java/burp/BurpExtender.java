package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension {
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
    private final ConcurrentHashMap<String, CompletableFuture<byte[]>> responseMap = new ConcurrentHashMap<>();
    private final AtomicInteger messageCounter = new AtomicInteger(0);
    private final Set<String> filteredRequests = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private static final byte[] MESSAGE_SEPARATOR = "\r\n====================================================\r\n".getBytes();
    private static final String REQUEST_PREFIX = "REQUEST:";
    private static final String RESPONSE_PREFIX = "RESPONSE:";
    private final ConcurrentHashMap<String, HttpRequestResponse> requestResponseMap = new ConcurrentHashMap<>();
    private final List<String> orderedMessages = Collections.synchronizedList(new ArrayList<>());
    private final ConcurrentHashMap<String, Integer> requestKeyToSequentialId = new ConcurrentHashMap<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("HTTP Forwarder");

        configManager = new ConfigManager(api);
        configManager.loadConfig();

        SwingUtilities.invokeLater(this::initializeUI);

        executorService = Executors.newCachedThreadPool();

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                processRequest(requestToBeSent);
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                processResponse(responseReceived);
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        new Thread(this::handleForwardedMessages).start();
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

    private void processRequest(HttpRequestToBeSent requestToBeSent) {
        if (!isRunning || persistentSocket == null || persistentSocket.isClosed()) return;

        executorService.submit(() -> {
            try {
                ByteArray requestBytes = requestToBeSent.toByteArray();
                String url = requestToBeSent.url();
                String method = requestToBeSent.method();
                String host = requestToBeSent.httpService().host();

                boolean shouldFilter = checkFilter(url, method, host);

                String requestKey = generateRequestKey(requestToBeSent);
                int sequentialId = messageCounter.getAndIncrement();
                requestKeyToSequentialId.put(requestKey, sequentialId);

                if (shouldFilter) {
                    filteredRequests.add(requestKey);
                    return;
                }

                CompletableFuture<byte[]> responseFuture = new CompletableFuture<>();
                responseMap.put(requestKey, responseFuture);

                byte[] requestData = requestBytes.getBytes();

                synchronized (persistentOutputStream) {
                    String message = String.format("%s%d\n%s", REQUEST_PREFIX, sequentialId, requestToBeSent.toString());
                    persistentOutputStream.write(message.getBytes());
                    persistentOutputStream.write(MESSAGE_SEPARATOR);
                    persistentOutputStream.flush();
                }

                orderedMessages.add(String.format("%s%d", REQUEST_PREFIX, sequentialId));

                requestResponseMap.put(requestKey, HttpRequestResponse.httpRequestResponse(requestToBeSent, null));

                try {
                    byte[] responseData = responseFuture.get(30, TimeUnit.SECONDS);
                    // Response will be handled in processResponse method
                } catch (InterruptedException | ExecutionException | TimeoutException e) {
                    logger.log(Level.WARNING, "等待响应时出错", e);
                } finally {
                    responseMap.remove(requestKey);
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "处理请求时出错", e);
            }
        });
    }

    private void processResponse(HttpResponseReceived responseReceived) {
        if (!isRunning || persistentSocket == null || persistentSocket.isClosed()) return;

        executorService.submit(() -> {
            try {
                ByteArray responseBytes = responseReceived.toByteArray();
                int statusCode = responseReceived.statusCode();

                String requestKey = generateRequestKey(responseReceived.initiatingRequest());
                Integer sequentialId = requestKeyToSequentialId.get(requestKey);

                if (sequentialId == null) {
                    logger.warning("未找到匹配的请求ID: " + requestKey);
                    return;
                }

                if (filteredRequests.remove(requestKey)) {
                    return;
                }

                boolean shouldFilter = checkFilter(statusCode);

                if (shouldFilter) {
                    return;
                }

                byte[] responseData = responseBytes.getBytes();

                synchronized (persistentOutputStream) {
                    String message = String.format("%s%d\n%s", RESPONSE_PREFIX, sequentialId, responseReceived.toString());
                    persistentOutputStream.write(message.getBytes());
                    persistentOutputStream.write(MESSAGE_SEPARATOR);
                    persistentOutputStream.flush();
                }

                orderedMessages.add(String.format("%s%d", RESPONSE_PREFIX, sequentialId));

                CompletableFuture<byte[]> responseFuture = responseMap.get(requestKey);
                if (responseFuture != null) {
                    responseFuture.complete(responseData);
                }

                HttpRequestResponse existingRequestResponse = requestResponseMap.get(requestKey);
                if (existingRequestResponse != null) {
                    HttpRequestResponse updatedRequestResponse = HttpRequestResponse.httpRequestResponse(
                        existingRequestResponse.request(),
                        responseReceived
                    );
                    requestResponseMap.put(requestKey, updatedRequestResponse);
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "处理响应时出错", e);
            }
        });
    }

    private void handleForwardedMessages() {
        while (isRunning) {
            try {
                String prefix = readLine(persistentInputStream);
                if (prefix == null) continue;

                int sequentialId;
                if (prefix.startsWith(REQUEST_PREFIX)) {
                    sequentialId = Integer.parseInt(prefix.substring(REQUEST_PREFIX.length()));
                } else if (prefix.startsWith(RESPONSE_PREFIX)) {
                    sequentialId = Integer.parseInt(prefix.substring(RESPONSE_PREFIX.length()));
                } else {
                    continue;
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = persistentInputStream.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                    if (endsWith(baos.toByteArray(), MESSAGE_SEPARATOR)) {
                        break;
                    }
                }

                byte[] data = Arrays.copyOf(baos.toByteArray(), baos.size() - MESSAGE_SEPARATOR.length);

                String message = new String(data);
                logger.info(String.format("%s%d\n%s", prefix, sequentialId, message));

            } catch (IOException e) {
                if (isRunning) {
                    logger.log(Level.SEVERE, "处理转发消息时出错", e);
                }
            }
        }
    }

    private boolean checkFilter(String url, String method, String host) {
        for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
            String filterMethod = (String) ruleTableModel.getValueAt(i, 1);
            String rule = (String) ruleTableModel.getValueAt(i, 2);
            boolean isActive = (Boolean) ruleTableModel.getValueAt(i, 3);

            if (!isActive) continue;

            switch (filterMethod) {
                case "文件名过滤":
                    if (url.toLowerCase().endsWith(rule.trim().toLowerCase())) {
                        return true;
                    }
                    break;
                case "域名过滤":
                    if (Pattern.matches(rule, host)) {
                        return true;
                    }
                    break;
                case "HTTP方法过滤":
                    if (method.equalsIgnoreCase(rule.trim())) {
                        return true;
                    }
                    break;
                case "IP过滤":
                    try {
                        String ip = InetAddress.getByName(host).getHostAddress();
                        if (ip.equals(rule.trim())) {
                            return true;
                        }
                    } catch (UnknownHostException e) {
                        logger.log(Level.WARNING, "无法解析主机名: " + host, e);
                    }
                    break;
            }
        }
        return false;
    }

    private boolean checkFilter(int statusCode) {
        for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
            String filterMethod = (String) ruleTableModel.getValueAt(i, 1);
            String rule = (String) ruleTableModel.getValueAt(i, 2);
            boolean isActive = (Boolean) ruleTableModel.getValueAt(i, 3);

            if (!isActive) continue;

            if (filterMethod.equals("状态码过滤") && String.valueOf(statusCode).equals(rule.trim())) {
                return true;
            }
        }
        return false;
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

    private String generateRequestKey(HttpRequest request) {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String uuid = UUID.randomUUID().toString();
        String bodyHash = calculateBodyHash(request);
        
        return request.method() + "|" + 
               request.url() + "|" + 
               request.httpService().host() + "|" + 
               request.httpService().port() + "|" +
               timestamp + "|" +
               uuid + "|" +
               bodyHash;
    }

    private String calculateBodyHash(HttpRequest request) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(request.body().getBytes());
            return bytesToHex(encodedHash);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.WARNING, "计算请求体哈希时出错", e);
            return "";
        }
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // 新增方法：获取有序的消息列表
    public List<String> getOrderedMessages() {
        return new ArrayList<>(orderedMessages);
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
