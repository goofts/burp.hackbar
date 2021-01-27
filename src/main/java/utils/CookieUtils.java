package utils;

import java.util.LinkedHashMap;
import java.util.List;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import config.HeaderEntry;

public class CookieUtils {
    public static String SPLITER = "::::";

    public static IHttpRequestResponse[] Reverse(IHttpRequestResponse[] input){
        for (int start = 0, end = input.length - 1; start < end; start++, end--) {
            IHttpRequestResponse temp = input[end];
            input[end] = input[start];
            input[start] = temp;
        }
        return input;
    }

    public static HeaderEntry getLatestHeaderFromHistory(String shortUrl, String headerName){
        shortUrl = HttpRequestResponseUtils.formateURLString(shortUrl);
        IHttpRequestResponse[]  historyMessages = Reverse(BurpExtender.mCallbacks.getProxyHistory());
        HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(BurpExtender.mCallbacks.getHelpers());

        for (IHttpRequestResponse historyMessage:historyMessages) {
            String hisShortUrl = httpRequestResponseUtils.getShortURL(historyMessage).toString();

            if (hisShortUrl.equalsIgnoreCase(shortUrl)) {
                String cookieValue = httpRequestResponseUtils.getHeaderValueOf(true,historyMessage,headerName);
                if (cookieValue != null){
                    HeaderEntry entry = new HeaderEntry(shortUrl,headerName,cookieValue, null);
                    return entry;
                    //return shortUrl+SPLITER+cookieValue;
                }
            }
        }

        return null;
    }

    public static HeaderEntry getLatestCookieFromHistory(String shortUrl){
        return getLatestHeaderFromHistory(shortUrl,"Cookie");
    }
    
    
    //Cookie: ISIC_SOP_DES_S22_NG_WEB=ISIC_SOP_DES_S22_NG_196_8; a_authorization_sit=18ac8987-2059-4a3b-a433-7def12dbae4d/97cd8cce-20ba-40df-ac44-0adae67ae2ad/BF32FB9F1479F653496C56DC99299483; custom.name=f12c5888-467d-49af-bcab-9cf4a44c03ff
    //判断字符串是否是合格的cookie，每个分号分割的部分是否都是键值对格式。
    public static boolean isCookieString(String input) {
        String cookieValue = input.trim();

        if (cookieValue.startsWith("Cookie:")){
            cookieValue = cookieValue.replaceFirst("Cookie:","").trim();
        }
        
        String[] items = input.split(";");
        for (String item: items) {
            item = item.trim();
            if (item.equals("")) {
                continue;
            }else if (!item.contains("=")) {
                return false;
            }
        }
        return true;
    }

    /*
    return a String url_which_cookie_from+SPLITER+cookievalue
     */
    public static HeaderEntry getLatestCookieFromSpeicified() {
        HeaderEntry latestCookie = null;
        String domainOrCookie = MethodsUtils.promptAndValidateInput("cookie OR cookie of ", null);
        String url1 = "";
        String url2 = "";
        try{
            if (domainOrCookie == null){
                return null;
            }else if (isCookieString(domainOrCookie)){//直接是cookie
                String cookieValue = domainOrCookie.trim();

                if (cookieValue.startsWith("Cookie:")){
                    cookieValue = cookieValue.replaceFirst("Cookie:","").trim();
                }
                String tips = "Cookie: "+cookieValue.substring(0,cookieValue.indexOf("="))+"...";
                latestCookie = new HeaderEntry(tips,"Cookie",cookieValue, null);

                return latestCookie;
            }else if (domainOrCookie.startsWith("http://") || domainOrCookie.startsWith("https://")) {//不包含协议头的域名或url
                url1 = domainOrCookie;
            }else {
                url1 = "http://"+domainOrCookie;
                url2 = "https://"+domainOrCookie;
            }

            try {
                url1 = HttpRequestResponseUtils.formateURLString(url1);
                url2 = HttpRequestResponseUtils.formateURLString(url2);
                latestCookie = getLatestCookieFromHistory(url1);
                if (latestCookie == null && url2 != ""){
                    latestCookie = getLatestCookieFromHistory(url2);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return latestCookie;

        }catch(NumberFormatException nfe){
            MethodsUtils.showMessage("Enter proper domain!!!", "Input Not Valid");
        }
        return null;
    }

    public static byte[] updateCookie(IHttpRequestResponse messageInfo,String cookieValue){
        HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(BurpExtender.mCallbacks.getHelpers());
        LinkedHashMap<String, String> headers = httpRequestResponseUtils.getHeaderMap(true,messageInfo);
        byte[] body = httpRequestResponseUtils.getBody(true,messageInfo);

        if(cookieValue.startsWith("Cookie: ")) {
            cookieValue = cookieValue.replaceFirst("Cookie: ","");
        }
        headers.put("Cookie",cookieValue);
        List<String> headerList = httpRequestResponseUtils.headerMapToHeaderList(headers);

        byte[] newRequestBytes = BurpExtender.mCallbacks.getHelpers().buildHttpMessage(headerList, body);
        return newRequestBytes;
    }
}