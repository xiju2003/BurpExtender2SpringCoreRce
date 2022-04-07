package burp;

import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Bootstrap.CustomBurpUrl;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import burp.Ui.ScanQueueTag;
import burp.Ui.Tags;
public class BurpExtender implements IScannerCheck,IBurpExtender{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IHttpRequestResponse resultRequestResponse;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private Tags tags;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.callbacks.setExtensionName("Burp2SpringCoreRce");//插件名字
        this.callbacks.setProxyInterceptionEnabled(false);
        callbacks.registerScannerCheck(this);
        tags = new Tags(this.callbacks,"SpringCoreScan") ;
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("Extender is working");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        // 判断是否开启插件
        if (!this.tags.getBaseSettingTagClass().isStart()) {
            return null;
        }

        //判断是否未检测目标
        String whiteListStr =  this.tags.getBaseSettingTagClass().Whitelist();
        List<String> whiteList = new ArrayList<>();
        if(!whiteListStr.equals("")){
            String[] in =  whiteListStr.split(";");
            for( int i=0;i<in.length;i++){
                whiteList.add(in[i]);
            }
        }
        String host = baseRequestResponse.getHttpService().getHost();
        String flag = "0";
        if (whiteList.size()!=0){
            flag = "1";
            for(String str : whiteList){
                if (str.contains(host)){
                    flag="0";
                    this.stdout.println("check white host:"+host);
                }
            }
        }

        if (flag.equals("1")){
            this.stdout.println(host+"is not target");
            return null;
        }

        String Method =  helpers.analyzeRequest(baseRequestResponse).getMethod();
        this.stdout.println("Method:"+Method);
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, baseRequestResponse);
        // 基础请求分析
        BurpAnalyzedRequest baseAnalyzedRequest = new BurpAnalyzedRequest(this.callbacks, this.tags, baseRequestResponse);

        //加入Table
        int tagId = this.tags.getScanQueueTagClass().add(
                "",
                this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                baseBurpUrl.getHttpRequestUrl().toString(),
                this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                "waiting for test results",
                baseRequestResponse
        );

            IScanIssue Detail = this.checkSpringRce(tagId, baseAnalyzedRequest,Method);
            if(Detail!=null){
                issues.add(Detail);
                return issues;
            }
            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "ALL",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "[-] not found Spring Core Rce",
                    baseRequestResponse
            );


        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
    /**
    * Check Spring Core RCE
    * */
    private IScanIssue checkSpringRce(int tagId, BurpAnalyzedRequest analyzedRequest,String Method)  {

        if (!this.tags.getBaseSettingTagClass().isStart()) {
            return null;
        }
        BurpAnalyzedRequest newanalyzedRequest = analyzedRequest;
        List<String> responseHeaders;
        IHttpRequestResponse newHttpRequestResponse;
        if (Method.equals("GET")){
            List<String> headers = new ArrayList<>();
            String payload = "class.module.classLoader.DefaultAssertionStatus=x";
             newHttpRequestResponse = newanalyzedRequest.makeHttpRequest(payload, headers,Method);

            responseHeaders = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getHeaders();
        }else {
            List<String> headers = new ArrayList<>();
            headers.add("Content-Type: application/x-www-form-urlencoded");
            String payload = "class.module.classLoader.DefaultAssertionStatus=x";
             newHttpRequestResponse = newanalyzedRequest.makeHttpRequest(payload, headers, Method);
            responseHeaders = this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getHeaders();
        }

        //给requestResponseEditor 赋值

        this.resultRequestResponse = newHttpRequestResponse;
        int flag = 0;
        for (String s : responseHeaders) {
            this.stdout.println(s);
            if (s.contains("\"status\":400")){
                flag = 1;
            }
        }
        if (flag == 1){
            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "",
                    this.helpers.analyzeRequest(newHttpRequestResponse).getMethod(),
                    new CustomBurpUrl(this.callbacks, newHttpRequestResponse).getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() + "",
                    "[+] found Spring Core RCE",
                    newHttpRequestResponse
            );

            String str1 = String.format("<br/>=============springCoreRce============<br/>");
            String str2 = String.format("The Host: %s <br/>", newHttpRequestResponse.getHttpService().getHost());
            String str3 = String.format("The Path: %s <br/>", this.helpers.analyzeRequest(newHttpRequestResponse).getUrl());
            String str5 = String.format("=====================================<br/>");

            String detail = str1 + str2 + str3  + str5;
            String issueName = "find SpringCoreRce;";
            flag = 0;
            return new CustomScanIssue(
                    this.helpers.analyzeRequest(newHttpRequestResponse).getUrl(),
                    issueName,
                    0,
                    "High",
                    "Certain",
                    null,
                    null,
                    detail,
                    null,
                    new IHttpRequestResponse[]{newHttpRequestResponse},
                    newHttpRequestResponse.getHttpService()
            );
        }else {
            this.stdout.println("not Found \"status\":400");
            this.tags.getScanQueueTagClass().save(
                    tagId,
                    "",
                    this.helpers.analyzeRequest(newHttpRequestResponse).getMethod(),
                    new CustomBurpUrl(this.callbacks, newHttpRequestResponse).getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(newHttpRequestResponse.getResponse()).getStatusCode() + "",
                    "[+]no found Spring Core RCE",
                    newHttpRequestResponse
            );
            return new CustomScanIssue(
                    this.helpers.analyzeRequest(newHttpRequestResponse).getUrl(),
                    "",
                    0,
                    "High",
                    "Certain",
                    null,
                    null,
                    "",
                    null,
                    new IHttpRequestResponse[]{newHttpRequestResponse},
                    newHttpRequestResponse.getHttpService());
        }


    }
}
