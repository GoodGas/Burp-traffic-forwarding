package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
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
    private JButton testConnectionButton;
    private JButton startButton;
    private JButton stopButton;
    private JButton addRuleButton;
    private JButton deleteRuleButton;
    private JButton saveConfigButton;
    private JButton exportConfigButton;
    private JButton importConfigButton;
    private JTable ruleTable;
    private DefaultTableModel ruleTableModel;
    private String forwardingIp;
    private int forwardingPort;
    private ExecutorService executorService;
    private boolean isRunning = false;
    private List<Rule> rules;
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
        mainPanel = new JPanel(new BorderLayout());

        // 顶部面板
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(new JLabel("转发服务器 IP:"));
        serverIpField = new JTextField(15);
        serverIpField.setText(config.getProperty("forwardingIp", ""));
        topPanel.add(serverIpField);

        topPanel.add(new JLabel("端口:"));
        serverPortField = new JTextField(5);
        serverPortField.setText(config.getProperty("forwardingPort", ""));
        topPanel.add(serverPortField);

        testConnectionButton = new JButton("测试连接");
        topPanel.add(testConnectionButton);

        startButton = new JButton("开始连接");
        topPanel.add(startButton);

        stopButton = new JButton("停止连接");
        stopButton.setEnabled(false);
        topPanel.add(stopButton);

        mainPanel.add(topPanel, BorderLayout.NORTH);

        // 中间规则表
        String[] columnNames = {"序号", "过滤方法", "过滤规则", "规则状态", "规则备注"};
        ruleTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // 仅允许编辑备注列
                return column == 4;
            }
        };

        ruleTable = new JTable(ruleTableModel);
        ruleTable.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                           boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                label.setHorizontalAlignment(SwingConstants.CENTER);
                label.setFont(label.getFont().deriveFont(Font.BOLD));
                return label;
            }
        });

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        for (int i = 0; i < ruleTable.getColumnCount(); i++) {
            ruleTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }

        JScrollPane scrollPane = new JScrollPane(ruleTable);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // 底部按钮面板
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addRuleButton = new JButton("添加规则");
        bottomPanel.add(addRuleButton);

        deleteRuleButton = new JButton("删除规则");
        bottomPanel.add(deleteRuleButton);

        saveConfigButton = new JButton("保存配置");
        bottomPanel.add(saveConfigButton);

        exportConfigButton = new JButton("导出配置");
        bottomPanel.add(exportConfigButton);

        importConfigButton = new JButton("导入配置");
        bottomPanel.add(importConfigButton);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        // 添加事件监听器
        testConnectionButton.addActionListener(e -> testConnection());
        startButton.addActionListener(e -> startLogging());
        stopButton.addActionListener(e -> stopLogging());
        addRuleButton.addActionListener(e -> addRule());
        deleteRuleButton.addActionListener(e -> deleteRule());
        saveConfigButton.addActionListener(e -> saveConfig());
        exportConfigButton.addActionListener(e -> exportConfig());
        importConfigButton.addActionListener(e -> importConfig());

        // 加载已保存的规则
        loadRules();
    }

    private void loadConfig() {
        config = new Properties();
        try (FileInputStream in = new FileInputStream(CONFIG_FILE)) {
            config.load(in);
        } catch (IOException e) {
            callbacks.printError("无法加载配置文件: " + e.getMessage());
        }
        rules = new ArrayList<>();
    }

    private void saveConfig() {
        config.setProperty("forwardingIp", forwardingIp);
        config.setProperty("forwardingPort", String.valueOf(forwardingPort));
        
        // 保存规则
        StringBuilder rulesStr = new StringBuilder();
        for (Rule rule : rules) {
            rulesStr.append(rule.toString()).append(";");
        }
        config.setProperty("rules", rulesStr.toString());

        try (FileOutputStream out = new FileOutputStream(CONFIG_FILE)) {
            config.store(out, "日志记录和转发器配置");
            JOptionPane.showMessageDialog(mainPanel, "配置已成功保存！");
        } catch (IOException e) {
            callbacks.printError("无法保存配置文件: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel, "保存配置失败: " + e.getMessage());
        }
    }

    private void loadRules() {
        String rulesStr = config.getProperty("rules", "");
        String[] ruleStrings = rulesStr.split(";");
        for (String ruleStr : ruleStrings) {
            if (!ruleStr.isEmpty()) {
                Rule rule = Rule.fromString(ruleStr);
                rules.add(rule);
                addRuleToTable(rule);
            }
        }
    }

    private void addRuleToTable(Rule rule) {
        ruleTableModel.addRow(new Object[]{
            ruleTableModel.getRowCount() + 1,
            rule.getFilterType(),
            rule.getFilterRule(),
            rule.isEnabled() ? "Open" : "Closed",
            rule.getComment()
        });
    }

    private void addRule() {
        String[] filterTypes = {"黑名单扩展名", "域名过滤", "HTTP方法过滤", "状态码过滤", "IP过滤"};
        JComboBox<String> filterTypeCombo = new JComboBox<>(filterTypes);
        JTextField filterRuleField = new JTextField(20);
        JCheckBox enabledCheckBox = new JCheckBox("启用", true);
        JTextField commentField = new JTextField(20);

        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(new JLabel("过滤方法:"));
        panel.add(filterTypeCombo);
        panel.add(new JLabel("过滤规则:"));
        panel.add(filterRuleField);
        panel.add(enabledCheckBox);
        panel.add(new JLabel("规则备注:"));
        panel.add(commentField);

        int result = JOptionPane.showConfirmDialog(mainPanel, panel, "添加规则",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            Rule rule = new Rule(
                (String) filterTypeCombo.getSelectedItem(),
                filterRuleField.getText(),
                enabledCheckBox.isSelected(),
                commentField.getText()
            );
            rules.add(rule);
            addRuleToTable(rule);
        }
    }

    private void deleteRule() {
        int selectedRow = ruleTable.getSelectedRow();
        if (selectedRow != -1) {
            rules.remove(selectedRow);
            ruleTableModel.removeRow(selectedRow);
            // 更新序号
            for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                ruleTableModel.setValueAt(i + 1, i, 0);
            }
        } else {
            JOptionPane.showMessageDialog(mainPanel, "请选择要删除的规则。");
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

        saveConfig();

        logQueue = new LinkedBlockingQueue<>(1000);
        executorService = Executors.newFixedThreadPool(10);
        scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        scheduledExecutorService.scheduleAtFixedRate(this::sendLogs, 0, 5, TimeUnit.SECONDS);

        isRunning = true;
        startButton.setEnabled(false);
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
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        JOptionPane.showMessageDialog(mainPanel, "日志记录已成功停止！");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isRunning) return;

        executorService.submit(() -> {
            try {
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                IResponseInfo responseInfo = messageIsRequest ? null : helpers.analyzeResponse(messageInfo.getResponse());
                String url = requestInfo.getUrl().toString().toLowerCase();
                
                for (Rule rule : rules) {
                    if (!rule.isEnabled()) continue;

                    switch (rule.getFilterType()) {
                        case "黑名单扩展名":
                            if (url.endsWith(rule.getFilterRule().toLowerCase())) return;
                            break;
                        case "域名过滤":
                            if (!url.matches(rule.getFilterRule())) return;
                            break;
                        case "HTTP方法过滤":
                            if (!requestInfo.getMethod().equalsIgnoreCase(rule.getFilterRule())) return;
                            break;
                        case "状态码过滤":
                            if (!messageIsRequest && responseInfo.getStatusCode() != Integer.parseInt(rule.getFilterRule())) return;
                            break;
                        case "IP过滤":
                            if (!requestInfo.getUrl().getHost().equals(rule.getFilterRule())) return;
                            break;
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
        
        // 清空规则表
        ruleTableModel.setRowCount(0);
        rules.clear();
        
        // 重新加载规则
        loadRules();
    }

    @Override
    public String getTabCaption() {
        return "日志记录和转发";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    private static class Rule {
        private String filterType;
        private String filterRule;
        private boolean enabled;
        private String comment;

        public Rule(String filterType, String filterRule, boolean enabled, String comment) {
            this.filterType = filterType;
            this.filterRule = filterRule;
            this.enabled = enabled;
            this.comment = comment;
        }

        public String getFilterType() {
            return filterType;
        }

        public String getFilterRule() {
            return filterRule;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public String getComment() {
            return comment;
        }

        @Override
        public String toString() {
            return filterType + "," + filterRule + "," + enabled + "," + comment;
        }

        public static Rule fromString(String str) {
            String[] parts = str.split(",");
            return new Rule(parts[0], parts[1], Boolean.parseBoolean(parts[2]), parts[3]);
        }
    }
}
