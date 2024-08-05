package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private JPanel mainPanel;
    private JTextField forwardUrlField;
    private JTextField regexField;
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Request/Response Forwarder");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.registerHttpListener(this);
        
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                mainPanel = new JPanel();
                mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
                
                JLabel forwardLabel = new JLabel("Forward URL:");
                forwardUrlField = new JTextField(20);
                forwardUrlField.setText("http://example.com/forward");
                
                JLabel regexLabel = new JLabel("URL Regex Pattern:");
                regexField = new JTextField(20);
                regexField.setText(".*");  // 默认匹配所有URL
                
                mainPanel.add(forwardLabel);
                mainPanel.add(forwardUrlField);
                mainPanel.add(regexLabel);
                mainPanel.add(regexField);
                
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        stdout.println("Request/Response Forwarder插件加载成功!");
    }

    @Override
    public String getTabCaption() {
        return "Forwarder";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();
        
        if (matchesRegex(url)) {
            if (messageIsRequest) {
                byte[] request = messageInfo.getRequest();
                forwardMessage(request, true, url);
            } else {
                byte[] response = messageInfo.getResponse();
                forwardMessage(response, false, url);
            }
        }
    }

    private boolean matchesRegex(String url) {
        String regex = regexField.getText();
        return Pattern.matches(regex, url);
    }

    private void forwardMessage(byte[] message, boolean isRequest, String originalUrl) {
        try {
            String forwardUrl = forwardUrlField.getText();
            URL url = new URL(forwardUrl);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setDoOutput(true);
            
            con.setRequestProperty("X-Message-Type", isRequest ? "Request" : "Response");
            con.setRequestProperty("X-Original-URL", originalUrl);

            try(OutputStream os = con.getOutputStream()) {
                os.write(message);
            }

            int responseCode = con.getResponseCode();
            stdout.println("转发" + (isRequest ? "请求" : "响应") + "到 " + forwardUrl + 
                           "，原始URL: " + originalUrl + "，响应代码: " + responseCode);

        } catch (Exception e) {
            stdout.println("转发失败: " + e.getMessage());
        }
    }
}
