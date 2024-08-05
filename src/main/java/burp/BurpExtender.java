package burp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JTextArea whitelistArea;
    private JTextArea blacklistArea;
    private JButton applyButton;
    
    private String forwardingIp;
    private int forwardingPort;
    private List<String> whitelist;
    private List<String> blacklist;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // 设置扩展名称
        callbacks.setExtensionName("Forwarding Config");

        // 初始化UI
        SwingUtilities.invokeLater(() -> {
            buildUI();
            // 在UI构建完成后添加标签
            callbacks.addSuiteTab(BurpExtender.this);
        });

        // 初始化列表
        whitelist = new ArrayList<>();
        blacklist = new ArrayList<>();

        // 注册HTTP监听器
        callbacks.registerHttpListener(this);
    }

    private void buildUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // Server IP and Port
        gbc.gridx = 0;
        gbc.gridy = 0;
        mainPanel.add(new JLabel("Forwarding Server IP:"), gbc);

        gbc.gridx = 1;
        serverIpField = new JTextField(15);
        mainPanel.add(serverIpField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        mainPanel.add(new JLabel("Forwarding Server Port:"), gbc);

        gbc.gridx = 1;
        serverPortField = new JTextField(5);
        mainPanel.add(serverPortField, gbc);

        // Whitelist and Blacklist
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        mainPanel.add(new JLabel("Whitelist (one domain per line):"), gbc);

        gbc.gridy = 3;
        whitelistArea = new JTextArea(10, 30);
        JScrollPane whitelistScroll = new JScrollPane(whitelistArea);
        mainPanel.add(whitelistScroll, gbc);

        gbc.gridy = 4;
        mainPanel.add(new JLabel("Blacklist (one domain per line):"), gbc);

        gbc.gridy = 5;
        blacklistArea = new JTextArea(10, 30);
        JScrollPane blacklistScroll = new JScrollPane(blacklistArea);
        mainPanel.add(blacklistScroll, gbc);

        // Apply button
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        applyButton = new JButton("Apply");
        mainPanel.add(applyButton, gbc);

        // Add action listener to the apply button
        applyButton.addActionListener(e -> applyConfiguration());
    }

    private void applyConfiguration() {
        // Get and validate the forwarding IP
        forwardingIp = serverIpField.getText().trim();
        if (forwardingIp.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter a valid forwarding IP address.");
            return;
        }

        // Get and validate the forwarding port
        try {
            forwardingPort = Integer.parseInt(serverPortField.getText().trim());
            if (forwardingPort <= 0 || forwardingPort > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter a valid port number (1-65535).");
            return;
        }

        // Update whitelist and blacklist
        whitelist = whitelistArea.getText().lines().filter(s -> !s.trim().isEmpty()).collect(Collectors.toList());
        blacklist = blacklistArea.getText().lines().filter(s -> !s.trim().isEmpty()).collect(Collectors.toList());

        JOptionPane.showMessageDialog(mainPanel, "Configuration applied successfully!");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 只处理来自 Proxy 工具的请求
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }

        if (forwardingIp == null || forwardingIp.isEmpty()) {
            return; // 没有配置转发
        }

        IHttpService originalService = messageInfo.getHttpService();
        String host = originalService.getHost();

        // 检查主机是否在白名单或黑名单中
        boolean shouldForward = whitelist.isEmpty() || whitelist.stream().anyMatch(host::contains);
        boolean isBlacklisted = blacklist.stream().anyMatch(host::contains);

        if (shouldForward && !isBlacklisted) {
            // 创建一个新的 HTTP 服务，使用转发服务器的详细信息
            IHttpService forwardingService = helpers.buildHttpService(forwardingIp, forwardingPort, originalService.getProtocol());

            // 更新消息的服务
            messageInfo.setHttpService(forwardingService);

            // 如果是请求，我们需要修改 Host 头
            if (messageIsRequest) {
                byte[] request = messageInfo.getRequest();
                IRequestInfo requestInfo = helpers.analyzeRequest(request);
                List<String> headers = requestInfo.getHeaders();

                // 修改或添加 Host 头
                headers.removeIf(header -> header.toLowerCase().startsWith("host:"));
                headers.add("Host: " + forwardingIp);

                // 重建请求
                byte[] body = request.clone();
                body = new String(body).substring(requestInfo.getBodyOffset()).getBytes();
                byte[] newRequest = helpers.buildHttpMessage(headers, body);

                // 设置修改后的请求
                messageInfo.setRequest(newRequest);
            }
        }
    }

    @Override
    public String getTabCaption() {
        return "Forwarding Config";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
