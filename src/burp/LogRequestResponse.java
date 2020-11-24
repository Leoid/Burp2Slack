package burp;

public class LogRequestResponse {
    final int tool;
    final IHttpRequestResponsePersisted requestResponse;
    final boolean messageIsRequest;

    LogRequestResponse(int tool, IHttpRequestResponsePersisted requestResponse, boolean messageIsRequest)
    {
        this.tool = tool;
        this.requestResponse = requestResponse;
        this.messageIsRequest = messageIsRequest;

    }
}
