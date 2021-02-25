package utils;

import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.swing.*;

public class MethodsUtils {
    public static JMenu createMultipleMenu(JMenu multiplemenu, String[] menuitems, String[][] submenuitems, Object actionListener){
        for(int i=0; i < menuitems.length; i++){
            JMenu menu = new JMenu(menuitems[i]);
            if(menuitems[i].equals("Basic Statements")){
                multiplemenu.add(new JSeparator());
                multiplemenu.add(addMenuItemAndListener(menu, submenuitems[i], actionListener));
                multiplemenu.add(new JSeparator());
            }else{
                multiplemenu.add(addMenuItemAndListener(menu, submenuitems[i], actionListener));
            }
        }
        return multiplemenu;
    }

    public static JMenu addMenuItemAndListener(JMenu menu, String[] itemList, Object actionListener){
        for(int i = 0; i < itemList.length; i++){
            JMenuItem item = new JMenuItem(itemList[i]);
            item.addActionListener((ActionListener) actionListener);
            menu.add(item);
        }
        return menu;
    }
    
    public static String promptAndValidateInput(String prompt, String str){
        String user_input = JOptionPane.showInputDialog(prompt, str);
        if (null == user_input) return  null;
        while(user_input.trim().equals("")){
            user_input = JOptionPane.showInputDialog(prompt, str);
        }
        return user_input.trim();
    }
    
    public static byte[] doModifyRequest(byte[] request, int[] selectedIndex, byte[] payloadByte){
        if (payloadByte == null){
            return request;
        }

        byte[] newRequest = new byte[request.length + payloadByte.length - (selectedIndex[1]-selectedIndex[0])];
        System.arraycopy(request, 0, newRequest, 0, selectedIndex[0]);//选中位置的前面部分
        System.arraycopy(payloadByte, 0, newRequest, selectedIndex[0], payloadByte.length);//新的内容替换选中内容
        System.arraycopy(request, selectedIndex[1], newRequest, selectedIndex[0]+payloadByte.length, request.length-selectedIndex[1]);//选中位置的后面部分
        return newRequest;
    }
    
    public static void showMessage(String str1, String str2){
        JOptionPane.showMessageDialog(null, str1, str2, 0);
    }

    public static List<String> getStrList(String inputString, int length) {
        int size = inputString.length() / length;
        if (inputString.length() % length != 0) {
            size += 1;
        }
        return getStrList(inputString, length, size);
    }

    public static List<String> getStrList(String inputString, int length,
                                          int size) {
        List<String> list = new ArrayList<String>();
        for (int index = 0; index < size; index++) {
            String childStr = substring(inputString, index * length,
                    (index + 1) * length);
            list.add(childStr);
        }
        return list;
    }

    public static String substring(String str, int f, int t) {
        if (f > str.length())
            return null;
        if (t > str.length()) {
            return str.substring(f, str.length());
        } else {
            return str.substring(f, t);
        }
    }

    public static String getRandomString(int length) {
        String str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        Random random = new Random();
        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = str.charAt(random.nextInt(str.length()));
        }
        return new String(text);
    }

    public static String decimalToHex(int decimal) {
        String hex = Integer.toHexString(decimal);
        return  hex.toUpperCase();
    }

    public static  byte[] encoding(byte[] body,int len,boolean useComment) throws UnsupportedEncodingException {
        String bodyString = new String(body, "UTF-8");

        List<String> str_list = MethodsUtils.getStrList(bodyString,len);
        String encoding_body = "";
        for(String str:str_list){
            if(useComment){
                encoding_body += String.format("%s;%s", MethodsUtils.decimalToHex(str.length()), MethodsUtils.getRandomString(10));
            }else{
                encoding_body += MethodsUtils.decimalToHex(str.length());
            }
            encoding_body += "\r\n";
            encoding_body += str;
            encoding_body += "\r\n";
        }
        encoding_body += "0\r\n\r\n";
        
        return encoding_body.getBytes();
    }

    public static byte[] decoding(byte[] body) throws UnsupportedEncodingException {
        String bodyStr = new String(body, "UTF-8");

        // decoding
        String[] array_body = bodyStr.split("\r\n");
        List<String> list_string_body = Arrays.asList(array_body);
        List<String> list_body = new ArrayList<String>(list_string_body);
        list_body.remove(list_body.size()-1);
        String decoding_body = "";
        for(int i=0;i<list_body.size();i++){
            int n = i%2;
            if(n != 0){
                decoding_body += list_body.get(i);
            }
        }

        return decoding_body.getBytes();
    }
}
