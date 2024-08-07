package burp;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JTextArea blacklistArea;
    private JTextField domainFilterField;
    private JTextField methodFilterField;
    private JTextField statusCodeFilterField;
    private JTextField ipFilterField;
    private JButton applyButton;
    private JButton stopButton;
    private JButton testConnectionButton;
    private JButton exportConfigButton;
    private JButton importConfigButton;
    private String forwardingIp;
    private int forwardingPort;
    private ExecutorService executorService;
    private boolean isRunning = false;
    private Set<String> blacklist;
    private Properties config;
    private static final String CONFIG_FILE = "logger_forwarder_config.properties";
    private BlockingQueue<String> logQueue;
    private ScheduledExecutorService scheduledExecutorService;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("增强型日志记录和转发器");

        loadConfig();

        SwingUtilities.invokeLater(() -> {
            buildUI();
            callbacks.addSuiteTab(BurpExtender.this);
        });

        callbacks.registerHttpListener(this);
    }

    private void buildUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Server IP and Port
        addLabelField("转发服务器 IP:", serverIpField = new JTextField(15), gbc, 0);
        serverIpField.setText(config.getProperty("forwardingIp", ""));

        addLabelField("转发服务器端口:", serverPortField = new JTextField(5), gbc, 1);
        serverPortField.setText(config.getProperty("forwardingPort", ""));

        // Buttons
        testConnectionButton = new JButton("测试连接");
        applyButton = new JButton("开始记录");
        stopButton = new JButton("停止记录");
        exportConfigButton = new JButton("导出配置");
        importConfigButton = new JButton("导入配置");

        stopButton.setEnabled(false);

        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.gridy = 2;
        mainPanel.add(testConnectionButton, gbc);
        gbc.gridx = 1;
        mainPanel.add(applyButton, gbc);
        gbc.gridx = 2;
        mainPanel.add(stopButton, gbc);
        gbc.gridx = 3;
        mainPanel.add(exportConfigButton, gbc);
        gbc.gridx = 4;
        mainPanel.add(importConfigButton, gbc);

        // Event handlers
        testConnectionButton.addActionListener(e -> testConnection());
        applyButton.addActionListener(e -> startLogging());
        stopButton.addActionListener(e -> stopLogging());
        exportConfigButton.addActionListener(e -> exportConfig());
        importConfigButton.addActionListener(e -> importConfig());

        // Filters
        addFilterPanel(gbc);
    }

    private void addLabelField(String label, JTextField field, GridBagConstraints gbc, int row) {
        gbc.gridx = 0;
        gbc.gridy = row;
        mainPanel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        mainPanel.add(field, gbc);
    }

    private void addFilterPanel(GridBagConstraints gbc) {
        JPanel filterPanel = new JPanel(new GridLayout(5, 2, 5, 5));
        filterPanel.add(new JLabel("黑名单扩展名 (逗号分隔):"));
        blacklistArea = new JTextArea(5, 20);
        blacklistArea.setText(config.getProperty("blacklist", ""));
        filterPanel.add(new JScrollPane(blacklistArea));

        filterPanel.add(new JLabel("域名过滤 (正则表达式):"));
        domainFilterField = new JTextField(15);
        domainFilterField.setText(config.getProperty("domainFilter", ""));
        filterPanel.add(domainFilterField);

        filterPanel.add(new JLabel("HTTP 方法过滤 (逗号分隔):"));
        methodFilterField = new JTextField(15);
        methodFilterField.setText(config.getProperty("methodFilter", ""));
        filterPanel.add(methodFilterField);

        filterPanel.add(new JLabel("状态码过滤 (逗号分隔):"));
        statusCodeFilterField = new JTextField(15);
        statusCodeFilterField.setText(config.getProperty("statusCodeFilter", ""));
        filterPanel.add(statusCodeFilterField);

        filterPanel.add(new JLabel("IP 过滤 (逗号分隔):"));
        ipFilterField = new JTextField(15);
        ipFilterField.setText(config.getProperty("ipFilter", ""));
        filterPanel.add(ipFilterField);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.BOTH;
        mainPanel.add(filterPanel, gbc);
    }

    private void loadConfig() {
        config = new Properties();
        try (FileInputStream in = new FileInputStream(CONFIG_FILE)) {
            config.load(in);
        } catch (IOException e) {
            callbacks.printError("无法加载配置文件: " + e.getMessage());
        }
    }

    private void saveConfig() {
        config.setProperty("forwardingIp", serverIpField.getText().trim());
        config.setProperty("forwardingPort", serverPortField.getText().trim());
        config.setProperty("blacklist", blacklistArea.getText());
        config.setProperty("domainFilter", domainFilterField.getText());
        config.setProperty("methodFilter", methodFilterField.getText());
        config.setProperty("statusCodeFilter", statusCodeFilterField.getText());
        config.setProperty("ipFilter", ipFilterField.getText());

        try (FileOutputStream out = new FileOutputStream(CONFIG_FILE)) {
            config.store(out, "日志记录和转发器配置");
        } catch (IOException e) {
            callbacks.printError("无法保存配置文件: " + e.getMessage());
        }
    }

    private void startLogging() {
        forwardingIp = serverIpField.getText().trim();
        if (forwardingIp.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入有效的转发 IP 地址。");
            return;
        }

        try {
            forwardingPort = Integer.parseInt(serverPortField.getText().trim());
            if (forwardingPort <= 0 || forwardingPort > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(mainPanel, "请输入有效的端口号 (1-65535)。");
            return;
        }

        updateBlacklist();
        saveConfig();

        logQueue = new LinkedBlockingQueue<>(1000);
        executorService = Executors.newFixedThreadPool(10);
        scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        scheduledExecutorService.scheduleAtFixedRate(this::sendLogs, 0, 5, TimeUnit.SECONDS);

        isRunning = true;
        applyButton.setEnabled(false);
        stopButton.setEnabled(true);
        JOptionPane.showMessageDialog(mainPanel, "日志记录已成功启动！");
    }

    private void stopLogging() {
        isRunning = false;
        if (executorService != null) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(800, TimeUnit.MILLISECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
            }
        }
        if (scheduledExecutorService != null) {
            scheduledExecutorService.shutdown();
        }
        applyButton.setEnabled(true);
        stopButton.setEnabled(false);
        JOptionPane.showMessageDialog(mainPanel, "日志记录已成功停止！");
    }

    private void updateBlacklist() {
        blacklist = new HashSet<>();
        String[] extensions = blacklistArea.getText().split(",");
        for (String ext : extensions) {
            ext = ext.trim().toLowerCase();
            if (!ext.isEmpty()) {
                if (!ext.startsWith(".")) {
                    ext = "." + ext;
                }
                blacklist.add(ext);
            }
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isRunning) return;

        executorService.submit(() -> {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                IResponseInfo responseInfo = messageIsRequest ? null : helpers.analyzeResponse(messageInfo.getResponse());
                String url = requestInfo.getUrl().toString().toLowerCase();

                // 扩展名过滤
                for (String ext : blacklist) {
                    if (url.endsWith(ext)) {
                        return;
                    }
                }

                // 域名过滤
                String domainFilter = domainFilterField.getText().trim();
                if (!domainFilter.isEmpty() && !url.matches(domainFilter)) {
                    return;
                }

                // HTTP方法过滤
                String methodFilter = methodFilterField.getText().trim();
                if (!methodFilter.isEmpty()) {
                    String[] methods = methodFilter.split(",");
                    boolean methodMatch = false;
                    for (String method : methods) {
                        if (requestInfo.getMethod().equalsIgnoreCase(method.trim())) {
                            methodMatch = true;
                            break;
                        }
                    }
                    if (!methodMatch) {
                        return;
                    }
                }

                // IP过滤
                String ipFilter = ipFilterField.getText().trim();
                if (!ipFilter.isEmpty()) {
                    String host = requestInfo.getUrl().getHost();
                    String[] ips = ipFilter.split(",");
                    boolean ipMatch = false;
                    for (String ip : ips) {
                        if (host.equals(ip.trim())) {
                            ipMatch = true;
                            break;
                        }
                    }
                    if (!ipMatch) {
                        return;
                    }
                }

                // 状态码过滤
                if (!messageIsRequest) {
                    String statusCodeFilter = statusCodeFilterField.getText().trim();
                    if (!statusCodeFilter.isEmpty()) {
                        String[] statusCodes = statusCodeFilter.split(",");
                        boolean statusCodeMatch = false;
                        for (String statusCode : statusCodes) {
                            if (String.valueOf(responseInfo.getStatusCode()).equals(statusCode.trim())) {
                                statusCodeMatch = true;
                                break;
                            }
                        }
                        if (!statusCodeMatch) {
                            return;
                        }
                    }
                }

                String toolName = callbacks.getToolName(toolFlag);
                String messageType = messageIsRequest ? "请求" : "响应";
                String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());

                StringBuilder logMessage = new StringBuilder();
                logMessage.append(String.format("[%s] [%s] [%s]\n", timestamp, toolName, messageType));

                logMessage.append(String.format("URL: %s\n", requestInfo.getUrl()));
                logMessage.append(String.format("方法: %s\n", requestInfo.getMethod()));

                if (!messageIsRequest) {
                    logMessage.append(String.format("状态码: %d\n", responseInfo.getStatusCode()));
                }

                byte[] message = messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse();
                logMessage.append(new String(message));
                logMessage.append("\n\n");

                logQueue.offer(logMessage.toString());
            } catch (Exception e) {
                callbacks.printError("处理 HTTP 消息时出错: " + e.getMessage());
            }
        });
    }

    private void sendLogs() {
        List<String> logs = new ArrayList<>();
        logQueue.drainTo(logs);

        if (!logs.isEmpty()) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(forwardingIp, forwardingPort), 5000);
                try (OutputStream out = socket.getOutputStream()) {
                    for (String log : logs) {
                        out.write(log.getBytes());
                    }
                    out.flush();
                }
            } catch (IOException e) {
                callbacks.printError("转发日志时出错: " + e.getMessage());
            }
        }
    }

    private void testConnection() {
        String ip = serverIpField.getText().trim();
        String portStr = serverPortField.getText().trim();

        if (ip.isEmpty() || portStr.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请输入服务器 IP 和端口。");
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(mainPanel, "请输入有效的端口号。");
            return;
        }

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), 5000);
            JOptionPane.showMessageDialog(mainPanel, "连接成功！");
        } catch (IOException e) {
            JOptionPane.showMessageDialog(mainPanel, "连接失败: " + e.getMessage());
        }
    }

    private void exportConfig() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择导出位置");
        if (fileChooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileOutputStream out = new FileOutputStream(file)) {
                config.store(out, "日志记录和转发器配置");
                JOptionPane.showMessageDialog(mainPanel, "配置已成功导出！");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出配置时出错: " + e.getMessage());
            }
        }
    }

    private void importConfig() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择要导入的配置文件");
        if (fileChooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileInputStream in = new FileInputStream(file)) {
                config.load(in);
                updateUIFromConfig();
                JOptionPane.showMessageDialog(mainPanel, "配置已成功导入！");
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导入配置时出错: " + e.getMessage());
            }
        }
    }

    private void updateUIFromConfig() {
        serverIpField.setText(config.getProperty("forwardingIp", ""));
        serverPortField.setText(config.getProperty("forwardingPort", ""));
        blacklistArea.setText(config.getProperty("blacklist", ""));
        domainFilterField.setText(config.getProperty("domainFilter", ""));
        methodFilterField.setText(config.getProperty("methodFilter", ""));
        statusCodeFilterField.setText(config.getProperty("statusCodeFilter", ""));
        ipFilterField.setText(config.getProperty("ipFilter", ""));
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
