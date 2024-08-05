package burp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IProxyListener {
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

        // 注册代理监听器
        callbacks.registerProxyListener(this);
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
        forwardingIp = serverIpField.getText().trim();
        try {
            forwardingPort = Integer.parseInt(serverPortField.getText().trim());
            if (forwardingPort < 1 || forwardingPort > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(mainPanel, "Invalid port number. Please enter a number between 1 and 65535.");
            return;
        }

        whitelist = new ArrayList<>(List.of(whitelistArea.getText().split("\n")));
        blacklist = new ArrayList<>(List.of(blacklistArea.getText().split("\n")));

        // Remove empty entries
        whitelist.removeIf(String::isEmpty);
        blacklist.removeIf(String::isEmpty);

        JOptionPane.showMessageDialog(mainPanel, "Forwarding configuration applied successfully!");
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (forwardingIp == null || forwardingIp.isEmpty()) {
            return; // No forwarding configured
        }

        IHttpRequestResponse messageInfo = message.getMessageInfo();
        IHttpService originalService = messageInfo.getHttpService();
        String host = originalService.getHost();

        // Check if the host is in the whitelist or blacklist
        boolean shouldForward = whitelist.isEmpty() || whitelist.stream().anyMatch(host::contains);
        boolean isBlacklisted = blacklist.stream().anyMatch(host::contains);

        if (shouldForward && !isBlacklisted) {
            // Create a new HTTP service with the forwarding server details
            IHttpService forwardingService = helpers.buildHttpService(forwardingIp, forwardingPort, originalService.getProtocol());

            // Update the message with the new service
            messageInfo.setHttpService(forwardingService);
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
