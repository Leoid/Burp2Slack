package burp;

import com.slack.api.Slack;
import com.slack.api.webhook.Payload;
import com.slack.api.webhook.WebhookResponse;

import java.awt.*;
import java.io.IOException;
import java.util.List;
import java.util.*;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    IBurpExtenderCallbacks callbacks;
    IHttpRequestResponsePersisted PerRequestResponse;

    protected String mPluginName = "Burp2Slack";


    public String hostname;
    public int port = 443;
    String serverkindcheck;
    private final List<LogRequestResponse> log = new ArrayList<LogRequestResponse>();
    public String getCurrentPayload;
    public static Timer timer;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        BurpExtenderTab.callbacks = callbacks;

        callbacks.setExtensionName("Burp2Slack Extension");
        callbacks.printOutput("Burp2Slack 1.0 loaded");

        BurpExtenderTab.configcomp = new ConfigComponent(callbacks);

        callbacks.registerHttpListener(this);
        callbacks.addSuiteTab(this);

    }


    @Override
    public String getTabCaption() {
        return BurpExtenderTab.tabName;
    }

    @Override
    public Component getUiComponent() {
        return BurpExtenderTab.configcomp.$$$getRootComponent$$$();
    }

    public void pushMessage() {
        // Get Options
        serverkindcheck = BurpExtenderTab.configcomp.servertypecomobox.getSelectedItem().toString();
        this.hostname = BurpExtenderTab.configcomp.slackURLtxtbox.getText().toString();


        if (!serverkindcheck.equals("Slack")) {
            if (!BurpExtenderTab.configcomp.serverporttxtbox.getText().toString().equals("")) {
                this.port = Integer.parseInt(BurpExtenderTab.configcomp.serverporttxtbox.getText().toString());
            }

            String requestGETTemplate = " HTTP/1.1\r\n" +
                    "Host: " + this.hostname + ":" + port + "\r\n" +
                    "User-Agent: Intruder2Slack/1.0\r\n" +
                    "\r\n\r\n";

            // Make the Request
            String request = "GET /?payload=" + callbacks.getHelpers().urlEncode(getCurrentPayload).toString() + " " + requestGETTemplate;
            byte[] requestBytes = callbacks.getHelpers().stringToBytes(request);
            byte[] responseBytes = callbacks.makeHttpRequest(this.hostname, port, false, requestBytes);


        } else {


            // Make the Request
            this.hostname = BurpExtenderTab.configcomp.slackURLtxtbox.getText().toString();


            Slack slack = Slack.getInstance();
            String webhookUrl = this.hostname;
            Payload payload = Payload.builder().text(getCurrentPayload).build();

            try {
                WebhookResponse response = slack.send(webhookUrl, payload);


            } catch (IOException e) {
                this.callbacks.printOutput("webhook error: "+e);
            }

        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {


        this.callbacks.saveBuffersToTempFiles(messageInfo);
        log.add(new LogRequestResponse(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo), messageIsRequest));
        int getPollSeconds = Integer.parseInt(BurpExtenderTab.configcomp.pollseconds.getText().toString());

        if (VariableManager.getisStart()) {
            timer = new Timer("Timer");
            TimerTask task = new TimerTask() {
                public void run() {

                    Match2Slack();

                }
            };


            timer.schedule(task, 1000, getPollSeconds);
            VariableManager.setisStart(false);
        }


    }

    public void Match2Slack() {
        // Loop through the saved Requests/Responses
        if (log.size() > 0) {
            for (int i = 0; i < log.size(); i++) {

                if (!log.get(i).messageIsRequest) {

                    IResponseInfo res = callbacks.getHelpers().analyzeResponse(log.get(i).requestResponse.getResponse());
                    // Parse Intruder Response
                    int responseStatusCode = res.getStatusCode();
                    ArrayList<String> responseHeaders = new ArrayList<>(res.getHeaders());


                    int bodyOffset = res.getBodyOffset();
                    byte[] byte_Request = log.get(i).requestResponse.getResponse();
                    byte[] byte_body = Arrays.copyOfRange(byte_Request, bodyOffset, byte_Request.length);

                    String responseBody = callbacks.getHelpers().bytesToString(byte_body);
                    responseBody = this.callbacks.getHelpers().urlEncode(responseBody).toString();


                    // Get response body textbox Index
                    int checkbody = responseBody.indexOf(BurpExtenderTab.configcomp.responsebodycontainstxtbox.getText().toString());
                    String responseBodyInput = BurpExtenderTab.configcomp.responsebodycontainstxtbox.getText().toString().replace("\"", "\\\"");

                    // Replace {{BODY}} with the following string. 100 chars before and after (to just focus on the matched payload).
                    String getBody = "";
                    int margin = 100;
                    if (checkbody != -1 ) {
                        if (checkbody > margin) {
                            if (checkbody + margin > responseBody.length()) {
                                getBody = responseBody.substring(checkbody - margin, responseBody.length());
                            } else {
                                getBody = responseBody.substring(checkbody - margin, checkbody + margin);
                            }
                        } else {
                            if(checkbody - margin < 0 && responseBody.length() > margin){
                            getBody = responseBody.substring(0, checkbody + margin);
                            }else{
                                getBody = responseBody.substring(0, responseBody.length());
                            }
                        }

                    }

                    int responseContentLength = responseBody.length();

                        // Checking IF {body contains}
                        if (BurpExtenderTab.configcomp.responsebodycontainstxtbox.getText().toString().length() > 0) {
                            if (checkbody!=-1) {
                                this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",responseBodyInput);
                                this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                pushMessage();

                            }
                        }

                        // Check Status Code
                        if (BurpExtenderTab.configcomp.httpstatuscodetxtbox.getText().toString().length() > 0) {
                            if (responseStatusCode == Integer.parseInt(BurpExtenderTab.configcomp.httpstatuscodetxtbox.getText().toString())

                            ) {
                                this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                        " " + responseStatusCode);
                                this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);

                                pushMessage();

                            }
                        }

                        // Check Headers
                        if (BurpExtenderTab.configcomp.responseheaderscontaintxtbox.getText().toString().length() > 0) {
                            for (int ii = 0; ii < responseHeaders.size(); ii++) {

                                if (responseHeaders.get(ii).toString().contains(BurpExtenderTab.configcomp.responseheaderscontaintxtbox.getText().toString())
                                ) {

                                    this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                            responseHeaders.get(ii).toString().replace("\"", "\\\""));
                                    this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", responseHeaders.get(ii).toString().replace("\"", "\\\""));
                                    pushMessage();
                                    ii = responseHeaders.size();


                                }

                            }
                        }

                        // Check Response Length
                        if (BurpExtenderTab.configcomp.contentlengthtxtbox.getText().toString().length() > 0) {
                            String contentlength = BurpExtenderTab.configcomp.contentlengthtxtbox.getText().toString();
                            char operator = contentlength.charAt(0);
                            int targetlength = Integer.parseInt(contentlength.substring(2, contentlength.length()));
                            switch (operator) {
                                case '>': {

                                    if (responseContentLength > targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " > " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);
                                        pushMessage();
                                    }
                                    break;
                                }
                                case '<': {
                                    if (responseContentLength < targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " < " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);
                                        pushMessage();
                                    }
                                    break;
                                }
                                case '=': {
                                    if (responseContentLength == targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " == " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);
                                        pushMessage();
                                    }
                                    break;
                                }
                                case '!': {
                                    if (responseContentLength != targetlength) {
                                        this.getCurrentPayload = BurpExtenderTab.configcomp.msgformattxtbox.getText().toString().replace("{{FOUND}}",
                                                " != " + targetlength);
                                        this.getCurrentPayload = this.getCurrentPayload.replace("{{BODY}}", getBody);
                                        pushMessage();
                                    }
                                    break;
                                }

                            }
                        }

                    }


                }



            //Clear
            log.clear();
        }

        if (!VariableManager.getisStart() && VariableManager.getstopTimer()) {
            timer.cancel();
            timer.purge();
        }


    }
}
