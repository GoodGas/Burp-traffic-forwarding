package burp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
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
    private List<Pattern> whitelistPatterns;
    private List<Pattern> blacklistPatterns;
    private boolean isConfigured = false;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("HTTP History Forwarder");

        SwingUtilities.invokeLater(() -> {
            buildUI();
            callbacks.addSuiteTab(BurpExtender.this);
        });

        whitelistPatterns = new ArrayList<>();
        blacklistPatterns = new ArrayList<>();

        callbacks.registerHttpListener(this);
    }

    private void buildUI() {
        mainPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

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

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        mainPanel.add(new JLabel("Whitelist (one regex per line):"), gbc);

        gbc.gridy = 3;
        whitelistArea = new JTextArea(10, 30);
        JScrollPane whitelistScroll = new JScrollPane(whitelistArea);
        mainPanel.add(whitelistScroll, gbc);

        gbc.gridy = 4;
        mainPanel.add(new JLabel("Blacklist (one regex per line):"), gbc);

        gbc.gridy = 5;
        blacklistArea = new JTextArea(10, 30);
        JScrollPane blacklistScroll = new JScrollPane(blacklistArea);
        mainPanel.add(blacklistScroll, gbc);

        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        applyButton = new JButton("Apply Configuration");
        mainPanel.add(applyButton, gbc);

        applyButton.addActionListener(e -> applyConfiguration());
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

        whitelistPatterns = compilePatterns(whitelistArea.getText());
        blacklistPatterns = compilePatterns(blacklistArea.getText());

        isConfigured = true;
        JOptionPane.showMessageDialog(mainPanel, "Configuration applied successfully! The plugin will now process HTTP history and new requests.");
        
        processExistingHttpHistory();
    }

    private List<Pattern> compilePatterns(String input) {
        return input.lines()
            .filter(s -> !s.trim().isEmpty())
            .map(s -> {
                try {
                    return Pattern.compile(s.trim(), Pattern.CASE_INSENSITIVE);
                } catch (Exception e) {
                    callbacks.printError("Invalid regex pattern: " + s);
                    return null;
                }
            })
            .filter(p -> p != null)
            .collect(Collectors.toList());
    }

    private void processExistingHttpHistory() {
        IHttpRequestResponse[] historyItems = callbacks.getProxyHistory();
        for (IHttpRequestResponse item : historyItems) {
            processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, item);
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isConfigured || !messageIsRequest) {
            return;
        }

        IHttpService originalService = messageInfo.getHttpService();
        String host = originalService.getHost();

        boolean shouldForward = whitelistPatterns.isEmpty() || whitelistPatterns.stream().anyMatch(p -> p.matcher(host).find());
        boolean isBlacklisted = blacklistPatterns.stream().anyMatch(p -> p.matcher(host).find());

        if (shouldForward && !isBlacklisted) {
            IHttpService forwardingService = helpers.buildHttpService(forwardingIp, forwardingPort, originalService.getProtocol());
            
            byte[] request = messageInfo.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            List<String> headers = requestInfo.getHeaders();

            headers.removeIf(header -> header.toLowerCase().startsWith("host:"));
            headers.add("Host: " + originalService.getHost());

            byte[] body = request.clone();
            body = new String(body).substring(requestInfo.getBodyOffset()).getBytes();
            byte[] newRequest = helpers.buildHttpMessage(headers, body);

            IHttpRequestResponse newRequestResponse = callbacks.makeHttpRequest(forwardingService, newRequest);
            
            // 如果需要处理响应，可以在这里添加代码
        }
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
