package utils;

import burp.*;
import config.ConfigEntry;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomUtils {
    public static boolean isWindows() {
        String OS_NAME = System.getProperties().getProperty("os.name").toLowerCase();
        //System.out.println(OS_NAME);
        if (OS_NAME.contains("windows")) {
            return true;
        } else {
            return false;
        }
    }

    public static boolean isWindows10() {
        String OS_NAME = System.getProperties().getProperty("os.name").toLowerCase();
        if (OS_NAME.equalsIgnoreCase("windows 10")) {
            return true;
        }
        return false;
    }

    public static boolean isMac(){
        String os = System.getProperty("os.name").toLowerCase();
        //Mac
        return (os.indexOf( "mac" ) >= 0); 
    }

    public static boolean isUnix(){
        String os = System.getProperty("os.name").toLowerCase();
        //linux or unix
        return (os.indexOf( "nix") >=0 || os.indexOf( "nux") >=0);
    }


    public static void browserOpen(Object url,String browser) throws Exception{
        String urlString = null;
        URI uri = null;
        if (url instanceof String) {
            urlString = (String) url;
            uri = new URI((String)url);
        }else if (url instanceof URL) {
            uri = ((URL)url).toURI();
            urlString = url.toString();
        }
        if(browser == null ||browser.equalsIgnoreCase("default") || browser.equalsIgnoreCase("")) {
            //whether null must be the first
            Desktop desktop = Desktop.getDesktop();
            if(Desktop.isDesktopSupported()&&desktop.isSupported(Desktop.Action.BROWSE)){
                desktop.browse(uri);
            }
        }else {
            Runtime runtime = Runtime.getRuntime();
            runtime.exec(browser+" "+urlString);
            //C:\Program Files\Mozilla Firefox\firefox.exe
            //C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe
        }
    }

    public static String stringToMD5(String plainText) {
        byte[] secretBytes = null;
        try {
            secretBytes = MessageDigest.getInstance("md5").digest(
                    plainText.getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("没有这个md5算法！");
        }
        String md5code = new BigInteger(1, secretBytes).toString(16);
        for (int i = 0; i < 32 - md5code.length(); i++) {
            md5code = "0" + md5code;
        }
        return md5code;
    }

    public static File saveFile(String defaultFileName) {
        try {
            JFileChooser fc =  new JFileChooser();
            if (fc.getCurrentDirectory() != null) {
                fc = new JFileChooser(fc.getCurrentDirectory());
            }else {
                fc = new JFileChooser();
            }

            fc.setDialogType(JFileChooser.CUSTOM_DIALOG);
            fc.setSelectedFile(new File(defaultFileName));

            int action = fc.showSaveDialog(null);

            if(action==JFileChooser.APPROVE_OPTION){
                File file=fc.getSelectedFile();
                return file;
            }
            return null;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static File selectPath() {
        try {
            JFileChooser fc =  new JFileChooser();
            if (fc.getCurrentDirectory() != null) {
                fc = new JFileChooser(fc.getCurrentDirectory());
            }else {
                fc = new JFileChooser();
            }

            fc.setDialogType(JFileChooser.CUSTOM_DIALOG);
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

            int action = fc.showSaveDialog(null);

            if(action==JFileChooser.APPROVE_OPTION){
                File path=fc.getSelectedFile();
                return path;
            }
            return null;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static File getFileName(IBurpExtenderCallbacks callbacks, IHttpRequestResponse reqresp, File rootPath) throws IOException {
        HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(callbacks.getHelpers());

        String pathStr = null;
        //1、从参数名中获取文件名称，任意文件读取多是这种情况
        List<IParameter> paras = httpRequestResponseUtils.getParas(reqresp);
        for (IParameter para:paras) {
            String value = para.getValue();
            int num = value.length()-value.replaceAll("/", "").length();
            if (num >=2) {
                pathStr = value;
                break;
            }
        }

        for (IParameter para:paras) {
            String value = para.getValue();
            int num = value.length()-value.replaceAll("\\\\", "").length();//是正则表达式
            if (num >=2) {
                pathStr = value;
                break;
            }
        }

        //2、使用url Path作为文件名，
        if (null == pathStr) {
            pathStr = httpRequestResponseUtils.getFullURL(reqresp).getPath();//getFile()包含了query中的内容
        }

        String canonicalFile = new File(pathStr).getCanonicalFile().toString();//移除所有位置切换符号
        //System.out.println("canonicalFile: "+canonicalFile);
        canonicalFile = canonicalFile.substring(canonicalFile.indexOf(File.separator));//如果是windows系统，需要去除磁盘符号

        File fullName = new File(rootPath,canonicalFile);
        //System.out.println("fullName: "+fullName);

        if (fullName.exists()){
            SimpleDateFormat simpleDateFormat =
                    new SimpleDateFormat("YYMMdd-HHmmss");
            String timeString = simpleDateFormat.format(new Date());
            fullName = new File(rootPath,canonicalFile+timeString);
        }
        return fullName;
    }

    public static int ChineseCount(byte[] input) {
        int num = 0;
        for (int i = 0; i < input.length; i++) {
            if (input[i] < 0) {
                num++;
                i = i + 1;
            }
        }
        return num;
    }

    //<script src="http://lbs.sf-express.com/api/map?v=2.0&ak=b1cfb18ca6864e46b3ed4cb18f12c0f8">
    //<script type=text/javascript src=./static/js/manifest.c7ad14f4845199970dcb.js>
    //<link rel="stylesheet" type="text/css" href="/cat/assets/css/bootstrap.min.css">
    //<link href=static/css/chunk-03d2ee16.a3503987.css rel=prefetch>
    //<link href="www.microsoft.com">这只会被当成目标，不会被当成域名
    //<link href="//www.microsoft.com">会被当成域名，协议会使用当前页面所使用的协议
    public static String getFullUrl(String url,IHttpRequestResponse message) {
        if (url.startsWith("http://") || url.startsWith("https://")) {
            //都是带有host的完整URL，直接访问即可
            return url;

        }else if(url.startsWith("//")) {//使用当前web的请求协议

            return message.getHttpService().getProtocol()+":"+url;

        }else if (url.startsWith("../") || url.startsWith("./") ) {

            return message.getHttpService().toString()+"/"+url;

        }else if(url.startsWith("/")){

            return message.getHttpService().toString()+url;

        }else{//没有斜杠的情况。<link href="www.microsoft.com">这只会被当成目标，不会被当成域名

            HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(BurpExtender.mCallbacks.getHelpers());
            String fullUrl = httpRequestResponseUtils.getFullURL(message).toString().split("\\?")[0];
            int indexOfLastSlash = fullUrl.lastIndexOf("/");//截取的内容不不包含当前index对应的元素
            return fullUrl.substring(0,indexOfLastSlash+1)+url;
        }
    }

    public static byte[] GetNewRequest(BurpExtender extender, byte[] request, String selectedString, int[] selectedIndex, String action){
        byte[] payloadBytes = null;
        String payload = extender.tableModel.getConfigValueByKey(action);

        if (extender.tableModel.getConfigTypeByKey(action).equals(ConfigEntry.Config_Custom_Payload)) {
            String host = extender.mInvocation.getSelectedMessages()[0].getHttpService().getHost();
            if (payload.contains("%host")) {
                payload = payload.replaceAll("%host", host);
            }

            if(payload.toLowerCase().contains("%dnslogserver")) {
                String dnslog = extender.tableModel.getConfigValueByKey("DNSlogServer");
                Pattern p = Pattern.compile("(?i)%dnslogserver");
                Matcher m  = p.matcher(payload);
                while ( m.find() ) {
                    String found = m.group(0);
                    payload = payload.replaceAll(found, dnslog);
                }
            }

            payloadBytes = payload.getBytes();
        }

        if (extender.tableModel.getConfigTypeByKey(action).equals(ConfigEntry.Config_Custom_Payload_Base64)) {
            payloadBytes = Base64.getDecoder().decode(payload);
        }

        if(payloadBytes == null) {
            payloadBytes = payload.getBytes();
        }

        return MethodsUtils.doModifyRequest(request, selectedIndex, payloadBytes);
    }

    public static boolean isInt(String input) {
        try {
            Integer b = Integer.valueOf(input);
            return true;
        } catch (NumberFormatException e) {
            try {
                long l = Long.valueOf(input);
                return true;
            }catch(Exception e1) {

            }
            return false;
        }
    }

    public static boolean isJSON(String test) {
        if (isJSONObject(test) || isJSONArray(test)) {
            return true;
        }else {
            return false;
        }
    }

    //org.json
    public static boolean isJSONObject(String test) {
        try {
            new JSONObject(test);
            return true;
        } catch (JSONException ex) {
            return false;
        }
    }


    public static boolean isJSONArray(String test) {
        try {
            new JSONArray(test);
            return true;
        } catch (JSONException ex) {
            return false;
        }
    }

    public static String updateJSONValue(String JSONString, String payload) throws Exception {

        if (isJSONObject(JSONString)) {
            JSONObject obj = new JSONObject(JSONString);
            Iterator<String> iterator = obj.keys();
            while (iterator.hasNext()) {
                String key = (String) iterator.next();        // We need to know keys of Jsonobject
                String value = obj.get(key).toString();


                if (isJSONObject(value)) {// if it's jsonobject
                    String newValue = updateJSONValue(value, payload);
                    obj.put(key,new JSONObject(newValue));
                }else if (isJSONArray(value)) {// if it's jsonarray
                    String newValue = updateJSONValue(value, payload);
                    obj.put(key,new JSONArray(newValue));
                }else {
                    obj.put(key, value+payload);
                }
            }
            return obj.toString();
        }else if(isJSONArray(JSONString)) {
            JSONArray jArray = new JSONArray(JSONString);

            ArrayList<String> newjArray = new ArrayList<String>();
            for (int i=0;i<jArray.length();i++) {//无论Array中的元素是JSONObject还是String都转换成String进行处理即可
                String item = jArray.get(i).toString();
                String newitem = updateJSONValue(item,payload);
                newjArray.add(newitem);
            }
            return newjArray.toString();
        }else {
            return JSONString+payload;
        }
    }
}