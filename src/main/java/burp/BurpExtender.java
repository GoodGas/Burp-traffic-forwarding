package burp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JTextArea whitelistArea;
    private JTextArea blacklistArea;
    private JButton applyButton;
    private JButton processHistoryButton;
    
    private String forwardingIp;
    private int forwardingPort;
    private List<String> whitelist;
    private List<String> blacklist;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("HTTP History Forwarder");

        SwingUtilities.invokeLater(() -> {
            buildUI();
            callbacks.addSuiteTab(BurpExtender.this);
        });

        whitelist = new ArrayList<>();
        blacklist = new ArrayList<>();
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
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.CENTER;
        applyButton = new JButton("Apply Configuration");
        mainPanel.add(applyButton, gbc);

        // Process History button
        gbc.gridx = 1;
        processHistoryButton = new JButton("Process HTTP History");
        mainPanel.add(processHistoryButton, gbc);

        applyButton.addActionListener(e -> applyConfiguration());
        processHistoryButton.addActionListener(e -> processHttpHistory());
    }

    private void applyConfiguration() {
        forwardingIp = serverIpField.getText().trim();
        if (forwardingIp.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter a valid forwarding IP address.");
            return;
        }

        try {
            forwardingPort = Integer.parseInt(serverPortField.getText().trim());
            if (forwardingPort <= 0 || forwardingPort > 65535) {
                throw new NumberFormatException();
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter a valid port number (1-65535).");
            return;
        }

        whitelist = whitelistArea.getText().lines().filter(s -> !s.trim().isEmpty()).collect(Collectors.toList());
        blacklist = blacklistArea.getText().lines().filter(s -> !s.trim().isEmpty()).collect(Collectors.toList());

        JOptionPane.showMessageDialog(mainPanel, "Configuration applied successfully!");
    }

    private void processHttpHistory() {
        if (forwardingIp == null || forwardingIp.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please apply a valid configuration first.");
            return;
        }

        IHttpRequestResponse[] historyItems = callbacks.getProxyHistory();
        int processedCount = 0;

        for (IHttpRequestResponse item : historyItems) {
            IHttpService originalService = item.getHttpService();
            String host = originalService.getHost();

            boolean shouldForward = whitelist.isEmpty() || whitelist.stream().anyMatch(host::contains);
            boolean isBlacklisted = blacklist.stream().anyMatch(host::contains);

            if (shouldForward && !isBlacklisted) {
                IHttpService forwardingService = helpers.buildHttpService(forwardingIp, forwardingPort, originalService.getProtocol());
                
                byte[] request = item.getRequest();
                IRequestInfo requestInfo = helpers.analyzeRequest(request);
                List<String> headers = requestInfo.getHeaders();

                headers.removeIf(header -> header.toLowerCase().startsWith("host:"));
                headers.add("Host: " + originalService.getHost());

                byte[] body = request.clone();
                body = new String(body).substring(requestInfo.getBodyOffset()).getBytes();
                byte[] newRequest = helpers.buildHttpMessage(headers, body);

                // 发送新的请求
                IHttpRequestResponse newRequestResponse = callbacks.makeHttpRequest(forwardingService, newRequest);
                
                // 可以在这里处理响应，如果需要的话
                
                processedCount++;
            }
        }

        JOptionPane.showMessageDialog(mainPanel, "Processed " + processedCount + " items from HTTP history.");
    }

    @Override
    public String getTabCaption() {
        return "HTTP History Forwarder";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
