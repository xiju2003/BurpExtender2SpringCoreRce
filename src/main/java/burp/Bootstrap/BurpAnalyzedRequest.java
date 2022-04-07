package burp.Bootstrap;

import java.io.PrintWriter;
import java.util.List;
import java.util.ArrayList;

import burp.*;
import burp.Ui.Tags;

public class BurpAnalyzedRequest {
    private IBurpExtenderCallbacks callbacks;

    private IExtensionHelpers helpers;

    private CustomBurpHelpers customBurpHelpers;

    private List<IParameter> jsonParameters = new ArrayList<>();
    private List<IParameter> eligibleJsonParameters = new ArrayList<>();

    private IHttpRequestResponse requestResponse;

    private Tags tags;
    private PrintWriter printWriter;
    public BurpAnalyzedRequest(IBurpExtenderCallbacks callbacks, Tags tags, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();

        this.tags = tags;
        this.printWriter = new PrintWriter(callbacks.getStdout(), true);
        this.customBurpHelpers = new CustomBurpHelpers(callbacks);
        this.requestResponse = requestResponse;

    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse.getRequest());
    }


    /**
     * 会根据程序类型自动组装请求的 请求发送接口
     */
    public IHttpRequestResponse makeHttpRequest(String payload, List<String> newHeaders, String method) {


        byte[] newRequest;
        List<String> headers = this.analyzeRequest().getHeaders();
        if (newHeaders != null && newHeaders.size() != 0) {
            headers.addAll(newHeaders);
        }
        int  i =0;
        for (String str : headers){

            if (str.contains("text/html")){
                headers.set(i,"Accept: application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            }
            i = i+1;
        }
        // 普通数据格式的处理
        if(method.equals("GET")){
            String path = headers.get(0);
            if (path.contains("?")){
                path = path.replace(" HTTP","&"+payload+" HTTP");
                this.printWriter.println(path);
                headers.set(0,path);
                newRequest = this.buildHttpMessage(headers);
            }else {
                path = path.replace(" HTTP","?"+payload+" HTTP");
                this.printWriter.println(path);
                headers.set(0,path);
                newRequest = this.buildHttpMessage(headers);
            }

        }else {
            newRequest = this.buildHttpMessage(headers,payload);
        }
        IHttpRequestResponse newHttpRequestResponse = this.callbacks.makeHttpRequest(this.requestResponse().getHttpService(), newRequest);
        return newHttpRequestResponse;
    }

    /**
     * json数据格式请求处理方法
     *
     * @param payload
     * @return
     */
    private byte[] buildHttpMessage(List<String> header,String payload) {
        byte[] newRequest = this.helpers.buildHttpMessage(
                header,
                this.helpers.stringToBytes(payload));
        return newRequest;
    }
    private byte[] buildHttpMessage(List<String> header) {
        byte[] newRequest = this.helpers.buildHttpMessage(
                header,
                this.helpers.stringToBytes(""));
        return newRequest;
    }
}

