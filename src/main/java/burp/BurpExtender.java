package burp;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTextField serverIpField;
    private JTextField serverPortField;
    private JButton applyButton;
    private String forwardingIp;
    private int forwardingPort;
    private ExecutorService executorService;
    private boolean isConfigured = false;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Multithreaded Logger and Forwarder");

        SwingUtilities.invokeLater(() -> {
            buildUI();
            callbacks.addSuiteTab(BurpExtender.this);
        });

        executorService = Executors.newFixedThreadPool(10); // 使用10个线程的线程池

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

        isConfigured = true;
        JOptionPane.showMessageDialog(mainPanel, "Configuration applied successfully!");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isConfigured) return;

        executorService.submit(() -> {
            try {
                String toolName = callbacks.getToolName(toolFlag);
                String messageType = messageIsRequest ? "REQUEST" : "RESPONSE";
                String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());

                StringBuilder logMessage = new StringBuilder();
                logMessage.append(String.format("[%s] [%s] [%s]\n", timestamp, toolName, messageType));

                if (messageIsRequest) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                    logMessage.append(String.format("URL: %s\n", requestInfo.getUrl()));
                    logMessage.append(String.format("Method: %s\n", requestInfo.getMethod()));
                } else {
                    IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
                    logMessage.append(String.format("Status Code: %d\n", responseInfo.getStatusCode()));
                }

                byte[] message = messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse();
                logMessage.append(new String(message));
                logMessage.append("\n\n");

                forwardLog(logMessage.toString());
            } catch (Exception e) {
                callbacks.printError("Error processing HTTP message: " + e.getMessage());
            }
        });
    }

    private void forwardLog(String logMessage) {
        try (Socket socket = new Socket(forwardingIp, forwardingPort);
             OutputStream out = socket.getOutputStream()) {
            out.write(logMessage.getBytes());
            out.flush();
        } catch (IOException e) {
            callbacks.printError("Error forwarding log: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return "Logger & Forwarder";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
