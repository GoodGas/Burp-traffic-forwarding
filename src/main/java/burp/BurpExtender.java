import burp.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private DefaultTableModel ruleTableModel;
    private Properties config;
    private boolean isRunning = false;
    private ExecutorService executorService;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("HTTP Request/Response Forwarder");

        SwingUtilities.invokeLater(this::initUI);

        loadConfig();
        executorService = Executors.newFixedThreadPool(10);

        callbacks.registerHttpListener(this);
    }

    private void initUI() {
        mainPanel = new JPanel(new BorderLayout());

        // 配置面板
        JPanel configPanel = new JPanel(new GridLayout(3, 2));
        JTextField ipField = new JTextField(config.getProperty("forwardingIp", ""));
        JTextField portField = new JTextField(config.getProperty("forwardingPort", ""));
        JButton saveConfigButton = new JButton("保存配置");

        configPanel.add(new JLabel("转发 IP:"));
        configPanel.add(ipField);
        configPanel.add(new JLabel("转发端口:"));
        configPanel.add(portField);
        configPanel.add(new JLabel());
        configPanel.add(saveConfigButton);

        saveConfigButton.addActionListener(e -> {
            config.setProperty("forwardingIp", ipField.getText());
            config.setProperty("forwardingPort", portField.getText());
            saveConfig();
        });

        // 规则表格
        String[] columnNames = {"ID", "过滤方法", "规则", "是否激活"};
        ruleTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 3 ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column != 0;
            }
        };
        JTable ruleTable = new JTable(ruleTableModel);
        JScrollPane tableScrollPane = new JScrollPane(ruleTable);

        // 规则操作按钮
        JPanel ruleButtonPanel = new JPanel();
        JButton addRuleButton = new JButton("添加规则");
        JButton removeRuleButton = new JButton("删除规则");
        JButton clearRulesButton = new JButton("清空规则");
        ruleButtonPanel.add(addRuleButton);
        ruleButtonPanel.add(removeRuleButton);
        ruleButtonPanel.add(clearRulesButton);

        addRuleButton.addActionListener(e -> addRule());
        removeRuleButton.addActionListener(e -> removeSelectedRule(ruleTable));
        clearRulesButton.addActionListener(e -> clearRules());

        // 开始/停止按钮
        JButton toggleButton = new JButton("开始");
        toggleButton.addActionListener(e -> {
            isRunning = !isRunning;
            toggleButton.setText(isRunning ? "停止" : "开始");
        });

        // 布局
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(configPanel, BorderLayout.NORTH);
        topPanel.add(toggleButton, BorderLayout.SOUTH);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(tableScrollPane, BorderLayout.CENTER);
        mainPanel.add(ruleButtonPanel, BorderLayout.SOUTH);

        callbacks.customizeUiComponent(mainPanel);
        callbacks.addSuiteTab(this);

        loadRules();
    }

    private void addRule() {
        String[] filterMethods = {"黑名单扩展名", "域名过滤", "HTTP方法过滤", "IP过滤", "状态码过滤"};
        String selectedMethod = (String) JOptionPane.showInputDialog(mainPanel,
                "选择过滤方法:", "添加规则", JOptionPane.QUESTION_MESSAGE, null,
                filterMethods, filterMethods[0]);

        if (selectedMethod != null) {
            String rule = JOptionPane.showInputDialog(mainPanel, "输入规则:");
            if (rule != null && !rule.trim().isEmpty()) {
                int id = ruleTableModel.getRowCount() + 1;
                ruleTableModel.addRow(new Object[]{String.valueOf(id), selectedMethod, rule, true});
                saveRules();
            }
        }
    }

    private void removeSelectedRule(JTable table) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow != -1) {
            ruleTableModel.removeRow(selectedRow);
            updateRuleIds();
            saveRules();
        }
    }

    private void clearRules() {
        ruleTableModel.setRowCount(0);
        saveRules();
    }

    private void updateRuleIds() {
        for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
            ruleTableModel.setValueAt(String.valueOf(i + 1), i, 0);
        }
    }

    private void loadConfig() {
        config = new Properties();
        try (FileInputStream in = new FileInputStream("forwarder_config.properties")) {
            config.load(in);
        } catch (IOException e) {
            callbacks.printError("加载配置文件失败: " + e.getMessage());
        }
    }

    private void saveConfig() {
        try (FileOutputStream out = new FileOutputStream("forwarder_config.properties")) {
            config.store(out, "Forwarder Configuration");
        } catch (IOException e) {
            callbacks.printError("保存配置文件失败: " + e.getMessage());
        }
    }

    private void loadRules() {
        try (BufferedReader reader = new BufferedReader(new FileReader("forwarder_rules.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\|");
                if (parts.length == 4) {
                    ruleTableModel.addRow(parts);
                }
            }
        } catch (IOException e) {
            callbacks.printError("加载规则失败: " + e.getMessage());
        }
    }

    private void saveRules() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("forwarder_rules.txt"))) {
            for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
                for (int j = 0; j < ruleTableModel.getColumnCount(); j++) {
                    writer.write(ruleTableModel.getValueAt(i, j).toString());
                    if (j < ruleTableModel.getColumnCount() - 1) {
                        writer.write("|");
                    }
                }
                writer.newLine();
            }
        } catch (IOException e) {
            callbacks.printError("保存规则失败: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return "Custom Forwarder";
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
                if (messageIsRequest) {
                    processRequest(messageInfo);
                } else {
                    processResponse(messageInfo);
                }
            } catch (Exception e) {
                callbacks.printError("处理 HTTP 消息时出错: " + e.getMessage());
            }
        });
    }

    private void processRequest(IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString().toLowerCase();

        if (shouldForward(url, requestInfo, true)) {
            String serverIp = config.getProperty("forwardingIp");
            int serverPort = Integer.parseInt(config.getProperty("forwardingPort"));
            forwardMessage(messageInfo.getRequest(), serverIp, serverPort, "请求");
        }
    }

    private void processResponse(IHttpRequestResponse messageInfo) {
        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString().toLowerCase();

        if (shouldForward(url, responseInfo, false)) {
            String serverIp = config.getProperty("forwardingIp");
            int serverPort = Integer.parseInt(config.getProperty("forwardingPort"));
            forwardMessage(messageInfo.getResponse(), serverIp, serverPort, "响应");
        }
    }

    private boolean shouldForward(String url, Object info, boolean isRequest) {
        for (int i = 0; i < ruleTableModel.getRowCount(); i++) {
            String filterMethod = (String) ruleTableModel.getValueAt(i, 1);
            String rule = (String) ruleTableModel.getValueAt(i, 2);
            boolean isActive = (Boolean) ruleTableModel.getValueAt(i, 3);

            if (!isActive) continue;

            switch (filterMethod) {
                case "黑名单扩展名":
                    if (url.endsWith(rule.trim().toLowerCase())) return false;
                    break;
                case "域名过滤":
                    if (!url.matches(rule)) return false;
                    break;
                case "HTTP方法过滤":
                    if (isRequest && !((IRequestInfo) info).getMethod().equalsIgnoreCase(rule.trim())) return false;
                    break;
                case "IP过滤":
                    try {
                        if (!new URL(url).getHost().equals(rule.trim())) return false;
                    } catch (Exception e) {
                        callbacks.printError("解析 URL 时出错: " + e.getMessage());
                    }
                    break;
                case "状态码过滤":
                    if (!isRequest && !String.valueOf(((IResponseInfo) info).getStatusCode()).equals(rule.trim())) return false;
                    break;
            }
        }
        return true;
    }

    private void forwardMessage(byte[] message, String serverIp, int serverPort, String messageType) {
        try (Socket socket = new Socket(serverIp, serverPort)) {
            OutputStream os = socket.getOutputStream();
            os.write(message);
            os.flush();
            callbacks.printOutput(messageType + "已成功转发到 " + serverIp + ":" + serverPort);
        } catch (IOException e) {
            callbacks.printError("转发" + messageType + "时出错: " + e.getMessage());
        }
    }
}
