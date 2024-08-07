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
    private Properties config;
    private Set<String> blacklist;
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
        buildUI();
        callbacks.addSuiteTab(this);
    }

    private void buildUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // 服务器设置
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

        // 过滤规则
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        mainPanel.add(new JLabel("过滤规则:"), gbc);

        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.BOTH;
        String[] columnNames = {"类型", "规则"};
        Object[][] data = {
            {"黑名单扩展名", config.getProperty("blacklist", "")},
            {"域名过滤", config.getProperty("domainFilter", "")},
            {"HTTP方法过滤", config.getProperty("methodFilter", "")},
            {"状态码过滤", config.getProperty("statusCodeFilter", "")},
            {"IP过滤", config.getProperty("ipFilter", "")}
        };
        JTable filterTable = new JTable(data, columnNames);
        JScrollPane scrollPane = new JScrollPane(filterTable);
        scrollPane.setPreferredSize(new Dimension(500, 150));
        mainPanel.add(scrollPane, gbc);

        // 按钮
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

        // 添加事件监听器
        applyButton.addActionListener(e -> startLogging());
        stopButton.addActionListener(e -> stopLogging());
        testConnectionButton.addActionListener(e -> testConnection());
        exportConfigButton.addActionListener(e -> exportConfig());
        importConfigButton.addActionListener(e -> importConfig());
    }

    private void updateFilters() {
        JTable filterTable = (JTable) ((JScrollPane) mainPanel.getComponent(2)).getViewport().getView();
        blacklist = new HashSet<>(Arrays.asList(((String) filterTable.getValueAt(0, 1)).split(",")));
        config.setProperty("blacklist", (String) filterTable.getValueAt(0, 1));
        config.setProperty("domainFilter", (String) filterTable.getValueAt(1, 1));
        config.setProperty("methodFilter", (String) filterTable.getValueAt(2, 1));
        config.setProperty("statusCodeFilter", (String) filterTable.getValueAt(3, 1));
        config.setProperty("ipFilter", (String) filterTable.getValueAt(4, 1));
    }

    private void startLogging() {
        updateFilters();
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
        fileChooser.setDialogTitle("选择导出位置");
        int userSelection = fileChooser.showSaveDialog(mainPanel);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try (FileOutputStream out = new FileOutputStream(fileToSave)) {
                updateFilters();
                config.store(out, "HTTP Logger Configuration");
                JOptionPane.showMessageDialog(mainPanel, "配置已导出。", "信息", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出配置时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importConfig() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择配置文件");
        int userSelection = fileChooser.showOpenDialog(mainPanel);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToLoad = fileChooser.getSelectedFile();
            try (FileInputStream in = new FileInputStream(fileToLoad)) {
                config.load(in);
                loadConfig();
                JOptionPane.showMessageDialog(mainPanel, "配置已导入。", "信息", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导入配置时出错: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void loadConfig() {
        if (serverIpField != null) {
            serverIpField.setText(config.getProperty("forwardingIp", ""));
        }
        if (serverPortField != null) {
            serverPortField.setText(config.getProperty("forwardingPort", ""));
        }
        blacklist = new HashSet<>(Arrays.asList(config.getProperty("blacklist", "").split(",")));
        
        if (mainPanel != null) {
            JTable filterTable = (JTable) ((JScrollPane) mainPanel.getComponent(2)).getViewport().getView();
            DefaultTableModel model = (DefaultTableModel) filterTable.getModel();
            model.setValueAt(config.getProperty("blacklist", ""), 0, 1);
            model.setValueAt(config.getProperty("domainFilter", ""), 1, 1);
            model.setValueAt(config.getProperty("methodFilter", ""), 2, 1);
            model.setValueAt(config.getProperty("statusCodeFilter", ""), 3, 1);
            model.setValueAt(config.getProperty("ipFilter", ""), 4, 1);
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
                
                JTable filterTable = (JTable) ((JScrollPane) mainPanel.getComponent(2)).getViewport().getView();
                
                // 扩展名过滤
                String[] blacklistExts = ((String) filterTable.getValueAt(0, 1)).split(",");
                for (String ext : blacklistExts) {
                    if (url.endsWith(ext.trim())) {
                        return;
                    }
                }
                
                // 域名过滤
                String domainFilter = (String) filterTable.getValueAt(1, 1);
                if (!domainFilter.isEmpty() && !url.matches(domainFilter)) {
                    return;
                }
                
                // HTTP方法过滤
                String methodFilter = (String) filterTable.getValueAt(2, 1);
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
                
                // 状态码过滤
                if (!messageIsRequest) {
                    String statusCodeFilter = (String) filterTable.getValueAt(3, 1);
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
                
                // IP过滤
                String ipFilter = (String) filterTable.getValueAt(4, 1);
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
            OutputStream out = socket.getOutputStream();
            out.write(messageInfo.getRequest());
            out.flush();

            InputStream in = socket.getInputStream();
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                response.write(buffer, 0, bytesRead);
            }

            messageInfo.setResponse(response.toByteArray());
        } catch (IOException e) {
            callbacks.printError("转发请求时出错: " + e.getMessage());
        }
    }
}
