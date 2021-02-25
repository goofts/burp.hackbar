package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JMenuItem;
import com.google.gson.Gson;
import config.ConfigEntry;
import config.HeaderEntry;
import utils.*;
import config.Config;
import ui.ConfigTable;
import model.ConfigTableModel;
import ui.ExtenderUIPanel;

public class BurpExtender extends ExtenderUIPanel implements IBurpExtender, IContextMenuFactory, ITab, IHttpListener,IProxyListener,IExtensionStateListener {
    private static final long serialVersionUID = 1L;
    private static final byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
    private static final byte CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
    private static final byte CONTEXT_MESSAGE_VIEWER_REQUEST = 2;
    private static final byte CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;
    private static final byte CONTEXT_TARGET_SITE_MAP_TREE = 4;
    private static final byte CONTEXT_TARGET_SITE_MAP_TABLE = 5;
    private static final byte CONTEXT_PROXY_HISTORY = 6;
    private static final byte CONTEXT_SCANNER_RESULTS = 7;
    private static final byte CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;
    private static final byte CONTEXT_INTRUDER_ATTACK_RESULTS = 9;
    private static final byte CONTEXT_SEARCH_RESULTS = 10;
    public static IContextMenuInvocation mInvocation;
    public static IBurpExtenderCallbacks mCallbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public int proxyServerIndex = -1;

    public static String extensionName = "hackbar";
    public static String version = "1.1.1";
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        this.mCallbacks = callbacks;
        flushStd();
        stdout.println(getBanner());

        table = new ConfigTable(new ConfigTableModel());
        configPanel.setViewportView(table);

        String content = callbacks.loadExtensionSetting(extensionName);
        if (content!=null) {
            config = new Gson().fromJson(content, Config.class);
            showToUI(config);
        }else {
            showToUI(new Gson().fromJson(initConfig(), Config.class));
        }

        table.setupTypeColumn();

        BurpU2CEditorTabFactory burpU2CEditorTabFactory = new BurpU2CEditorTabFactory(null, false, helpers, callbacks);
        BurpJsonEditorTabFactory burpJsonEditorTabFactory = new BurpJsonEditorTabFactory(null, false, helpers, callbacks);

        callbacks.setExtensionName(extensionName);
        callbacks.addSuiteTab(this);
        callbacks.registerMessageEditorTabFactory(burpU2CEditorTabFactory);
        callbacks.registerMessageEditorTabFactory(burpJsonEditorTabFactory);
        callbacks.registerContextMenuFactory(new BurpCookieMenu(callbacks));
        callbacks.registerContextMenuFactory(new BurpResponseMenu(callbacks));
        callbacks.registerContextMenuFactory(new BurpDownloadResponseMenu(callbacks));
        callbacks.registerContextMenuFactory(new IContextMenuFactory() {
            public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
                switch (invocation.getInvocationContext()) {
                    case CONTEXT_PROXY_HISTORY:
                    case CONTEXT_TARGET_SITE_MAP_TREE:
                    case CONTEXT_TARGET_SITE_MAP_TABLE:
                    case CONTEXT_MESSAGE_VIEWER_REQUEST:
                    case CONTEXT_MESSAGE_VIEWER_RESPONSE:
                        return Collections.singletonList(new JMenuItem(new BurpOpenPcapFileMenu(mCallbacks)));
                    default:
                        return Collections.emptyList();
                }
            }
        });
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
    }

    private static void flushStd(){
        try{
            stdout = new PrintWriter(mCallbacks.getStdout(), true);
            stderr = new PrintWriter(mCallbacks.getStderr(), true);
        }catch (Exception e){
            stdout = new PrintWriter(System.out, true);
            stderr = new PrintWriter(System.out, true);
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.mInvocation = invocation;
        ArrayList<JMenuItem> menu_item_list = new ArrayList<JMenuItem>();

        UpdateHeaderMenu updateHeader = new UpdateHeaderMenu(this, invocation);
        if (updateHeader.getItemCount()>0) {
            menu_item_list.add(updateHeader);
        }

        menu_item_list.add(new BurpChunkedEncodingMenu(this, invocation));
        menu_item_list.add(new BurpCustomPayloadMenu(this, invocation));
        menu_item_list.add(new BurpXssPayloadMenu(this, invocation));
        menu_item_list.add(new BurpSqlPayloadMenu(this, invocation));
        menu_item_list.add(new BurpShellMenu(this, invocation));
        menu_item_list.add(new BurpXXEPayloadMenu(this, invocation));
        menu_item_list.add(new SetCookieMenu(this, invocation));
        menu_item_list.add(new SetCookieWithHistoryMenu(this, invocation));
        menu_item_list.add(new UpdateCookieMenu(this, invocation));
        menu_item_list.add(new UpdateCookieWithHistoryMenu(this, invocation));

        Iterator<JMenuItem> it = menu_item_list.iterator();
        while (it.hasNext()) {
            JMenuItem item = it.next();
            if (item.getText()==null || item.getText().equals("")) {
                it.remove();
            }
        }

        return menu_item_list;
    }


    @Override
    public String getTabCaption() {
        return (extensionName);
    }

    @Override
    public Component getUiComponent() {
        return this.getContentPane();
    }

    @Override
    public void extensionUnloaded() {
        mCallbacks.saveExtensionSetting(extensionName, getAllConfig());
    }

    @Override
    public String initConfig() {
        config = new Config("default");
        tableModel = new ConfigTableModel();
        return getAllConfig();
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(helpers);
        if (messageIsRequest) {//丢弃干扰请求
            String url = httpRequestResponseUtils.getFullURL(message.getMessageInfo()).toString();
            if (isDismissed(url)){
                //enable = ACTION_DROP; disable = ACTION_DONT_INTERCEPT
                if (tableModel.getConfigValueByKey("DismissAction") == null) {
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
                    message.getMessageInfo().setComment("Dismissed-ACTION_DONT_INTERCEPT");
                }else {//default action
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                    message.getMessageInfo().setComment("Dismissed-ACTION_DROP");
                }
                message.getMessageInfo().setHighlight("gray");
                return;
            }
        }

        /*setCookie的实现方案1。请求和响应数据包的修改都由processProxyMessage函数来实现。这种情况下：
         * 在Proxy拦截处进行SetCookie的操作时，该函数已经被调用！这个函数的调用时在手动操作之前的。
         * 即是说，当这个函数第一次被调用时，还没来得及设置cookie，获取到的cookieToSetMap必然为空，所以需要rehook操作。
         *setCookie的实现方案2。主要目标是为了避免rehook，分两种情况分别处理。
         * 情况一：当当前是CONTEXT_MESSAGE_EDITOR_REQUEST的情况下（比如proxy和repeater中），
         * 更新请求的操作和updateCookie的操作一样，在手动操作时进行更新，而响应包由processProxyMessage来更新。
         * 情况二：除了上面的情况，请求包和响应包的更新都由processProxyMessage来实现，非proxy的情况下也不需要再rehook。
         *
         */
        HashMap<String, HeaderEntry> cookieToSetMap = config.getSetCookieMap();
        //stdout.println("processProxyMessage called when messageIsRequest="+messageIsRequest+" "+cookieToSetMap);
        if (cookieToSetMap != null && !cookieToSetMap.isEmpty()){//第二次调用如果cookie不为空，就走到这里

            IHttpRequestResponse messageInfo = message.getMessageInfo();
            //String CurrentUrl = messageInfo.getHttpService().toString();//这个方法获取到的url包含默认端口！

            String CurrentUrl = httpRequestResponseUtils.getShortURL(messageInfo).toString();
            //stderr.println(CurrentUrl+" "+targetUrl);
            HeaderEntry cookieToSet = cookieToSetMap.get(CurrentUrl);
            if (cookieToSet != null){

                String targetUrl = cookieToSet.getTargetUrl();
                String cookieValue = cookieToSet.getHeaderValue();

                if (messageIsRequest) {
                    if (!cookieToSet.isRequestUpdated()) {
                        byte[] newRequest = CookieUtils.updateCookie(messageInfo,cookieValue);
                        messageInfo.setRequest(newRequest);
                    }
                }else {
                    List<String> responseHeaders = httpRequestResponseUtils.getHeaderList(false,messageInfo);
                    byte[] responseBody = httpRequestResponseUtils.getBody(false,messageInfo);
                    List<String> setHeaders = GetSetCookieHeaders(cookieValue);
                    responseHeaders.addAll(setHeaders);

                    byte[] response = helpers.buildHttpMessage(responseHeaders,responseBody);

                    messageInfo.setResponse(response);
                    cookieToSetMap.remove(CurrentUrl);//only need to set once
                }
            }

        }
        /*改用方案二，无需再rehook
        else {//第一次调用必然走到这里
            message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK);
            //让burp在等待用户完成操作后再次调用，就相当于再次对request进行处理。
            //再次调用，即使走到了这里，也不会再增加调用次数，burp自己应该有控制。
        }*/

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            if (messageIsRequest) {
                HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(helpers);

                URL url = httpRequestResponseUtils.getFullURL(messageInfo);
                String host = httpRequestResponseUtils.getHost(messageInfo);
                LinkedHashMap<String, String> headers = httpRequestResponseUtils.getHeaderMap(messageIsRequest,messageInfo);
                byte[] body = httpRequestResponseUtils.getBody(messageIsRequest,messageInfo);

                boolean isRequestChanged = false;

                //remove header
                List<ConfigEntry> configEntries = tableModel.getConfigByType(ConfigEntry.Action_Remove_From_Headers);
                for (ConfigEntry entry : configEntries) {
                    String key = entry.getKey();
                    if (headers.remove(key) != null) {
                        isRequestChanged = true;
                    }
                }

                //add/update/append header
                if (toolFlag == (toolFlag & checkEnabledFor())) {
                    //if ((config.isOnlyForScope() && callbacks.isInScope(url))|| !config.isOnlyForScope()) {
                    if (!config.isOnlyForScope()|| mCallbacks.isInScope(url)){

                        List<ConfigEntry> updateOrAddEntries = tableModel.getConfigEntries();
                        for (ConfigEntry entry : updateOrAddEntries) {
                            String key = entry.getKey();
                            String value = entry.getValue();

                            if (value.contains("%host")) {
                                value = value.replaceAll("%host", host);
                                //stdout.println("3333"+value);
                            }

                            if (value.toLowerCase().contains("%dnslogserver")) {
                                String dnslog = tableModel.getConfigValueByKey("DNSlogServer");
                                Pattern p = Pattern.compile("(?u)%dnslogserver");
                                Matcher m = p.matcher(value);

                                while (m.find()) {
                                    String found = m.group(0);
                                    value = value.replaceAll(found, dnslog);
                                }
                            }

                            if (entry.getType().equals(ConfigEntry.Action_Add_Or_Replace_Header) && entry.isEnable()) {
                                headers.put(key, value);
                                isRequestChanged = true;

                            } else if (entry.getType().equals(ConfigEntry.Action_Append_To_header_value) && entry.isEnable()) {
                                value = headers.get(key) + value;
                                headers.put(key, value);
                                isRequestChanged = true;
                                //stdout.println("2222"+value);
                            } else if (entry.getKey().equalsIgnoreCase("Chunked-AutoEnable") && entry.isEnable()) {
                                headers.put("Transfer-Encoding", " chunked");
                                isRequestChanged = true;

                                try {
                                    boolean useComment = false;
                                    if (this.tableModel.getConfigValueByKey("Chunked-UseComment") != null) {
                                        useComment = true;
                                    }
                                    String lenStr = this.tableModel.getConfigValueByKey("Chunked-Length");
                                    int len = 10;
                                    if (lenStr != null) {
                                        len = Integer.parseInt(lenStr);
                                    }
                                    body = MethodsUtils.encoding(body, len, useComment);
                                } catch (UnsupportedEncodingException e) {
                                    stderr.print(e.getStackTrace());
                                }
                            }
                        }

                        ///proxy function should be here
                        //reference https://support.portswigger.net/customer/portal/questions/17350102-burp-upstream-proxy-settings-and-sethttpservice
                        String proxy = this.tableModel.getConfigValueByKey("Proxy-ServerList");
                        String mode = this.tableModel.getConfigValueByKey("Proxy-UseRandomMode");

                        if (proxy != null) {//if enable is false, will return null.
                            List<String> proxyList = Arrays.asList(proxy.split(";"));//如果字符串是以;结尾，会被自动丢弃

                            if (mode != null) {//random mode
                                proxyServerIndex = (int) (Math.random() * proxyList.size());
                                //proxyServerIndex = new Random().nextInt(proxyList.size());
                            } else {
                                proxyServerIndex = (proxyServerIndex + 1) % proxyList.size();
                            }
                            String proxyhost = proxyList.get(proxyServerIndex).split(":")[0].trim();
                            int port = Integer.parseInt(proxyList.get(proxyServerIndex).split(":")[1].trim());

                            messageInfo.setHttpService(helpers.buildHttpService(proxyhost, port, messageInfo.getHttpService().getProtocol()));

                            String method = helpers.analyzeRequest(messageInfo).getMethod();
                            headers.put(method, url.toString());
                            isRequestChanged = true;
                            //success or failed,need to check?
                        }

                    }
                }
                if (isRequestChanged){
                    //set final request
                    List<String> headerList = httpRequestResponseUtils.headerMapToHeaderList(headers);
                    messageInfo.setRequest(helpers.buildHttpMessage(headerList,body));
                }

                if (isRequestChanged) {
                    List<String> finalheaders = helpers.analyzeRequest(messageInfo).getHeaders();
                    for (String entry : finalheaders) {
                        stdout.println(entry);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace(stderr);
        }
    }

    public List<String> GetSetCookieHeaders(String cookies){
        if (cookies.startsWith("Cookie: ")){
            cookies = cookies.replaceFirst("Cookie: ","");
        }

        String[] cookieList = cookies.split("; ");
        List<String> setHeaderList= new ArrayList<String>();
        for (String cookie: cookieList){
            setHeaderList.add(String.format("Set-Cookie: %s; Path=/",cookie));
        }

        return setHeaderList;
    }

    public boolean isDismissedURL(String url) {
        Set<String> dissmissed  = tableModel.getConfigValueSetByKey("DismissedURL");
        for (String disurl:dissmissed) {
            try {
                if (url.contains("?")){
                    url = url.substring(0,url.indexOf("?"));
                }

                if (disurl.contains("?")){
                    disurl = disurl.substring(0,disurl.indexOf("?"));
                }

                URL currentUrl = new URL(url);
                URL disURL = new URL(disurl);
                if (currentUrl.equals(disURL)) {
                    return true;
                }
            }catch(Exception e) {
                e.printStackTrace();
                stderr.print(e.getStackTrace());
            }
        }
        return false;
    }

    public boolean isDismissedHost(String host){
        Set<String> dissmissed  = tableModel.getConfigValueSetByKey("DismissedHost");
        if (dissmissed.contains(host)) return true;
        Iterator<String> it = dissmissed.iterator();
        while (it.hasNext()){
            String dissmissedHost = it.next().trim();
            if (dissmissedHost.startsWith("*.")){
                dissmissedHost = dissmissedHost.replaceFirst("\\*","");
                if (host.trim().toLowerCase().endsWith(dissmissedHost.toLowerCase())){
                    return true;
                }
            }else if (dissmissedHost.equalsIgnoreCase(host.trim())){
                return true;
            }
        }
        return false;
    }


    public boolean isDismissed(String url) {
        try {
            String host = new URL(url).getHost();
            if (isDismissedHost(host)) {
                return true;
            }else {
                return isDismissedURL(url);
            }
        }catch(Exception e) {
            return false;
        }
    }

    public static String getBanner(){
        String bannerInfo =
                "[+] " + extensionName + " is loaded\n"
                        + "[+]\n"
                        + "[+] ###########################################################\n"
                        + "[+]    " + extensionName + " v" + version +"\n"
                        + "[+]    anthor:   bit4woo\n"
                        + "[+]    email:    bit4woo@163.com\n"
                        + "[+]    github:   https://github.com/bit4woo/knife\n"
                        + "[+]    modifier: goofts\n"
                        + "[+]    date:     2021/1/14\n"
                        + "[+] ###########################################################\n"
                        + "[+] Please enjoy it";
        return bannerInfo;
    }
}