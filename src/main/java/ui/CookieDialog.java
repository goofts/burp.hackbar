package ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import com.alibaba.fastjson.JSON;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CookieDialog
 * Cookie 弹窗功能实现
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class CookieDialog extends JDialog {
    private IHttpRequestResponse mReqResp;
    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private String strDomain;
    private String strRawCookie;
    private String strJsonCookie;
    private String strJsCookie;

    public CookieDialog(IBurpExtenderCallbacks callbacks, IHttpRequestResponse reqresp) {
        this.mCallbacks = callbacks;
        this.mReqResp = reqresp;
        this.mHelpers = mCallbacks.getHelpers();

        strDomain = mReqResp.getHttpService().getHost();
        List<String> headers = mHelpers.analyzeRequest(reqresp.getRequest()).getHeaders();

        strRawCookie = "extender=hackbar;";
        for (String str:headers) {
            int num = mHelpers.indexOf(str.getBytes(), "Cookie:".getBytes(), false, 0, str.length());
            if(num>=0){
                strRawCookie += str.substring(8);
            }
        }
        strJsonCookie = ToJson(strRawCookie);
        strJsCookie = ToJs(strRawCookie);

        initialze();
    }

    private void initialze(){
        Toolkit toolkit = Toolkit.getDefaultToolkit();
        int x = (int)(toolkit.getScreenSize().getWidth()-this.getWidth())/2;
        int y = (int)(toolkit.getScreenSize().getHeight()-this.getHeight())/2;

        this.setTitle("cookies");
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setLocationRelativeTo(null);
        this.setLayout(new BorderLayout());
        this.setLocation(x,y);
        this.setSize(360,560);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JPanel mPanel = new JPanel();
                mPanel.setLayout(new GridBagLayout());

                JButton btnFreshen = new JButton("Freshen");
                JLabel lbDomain = new JLabel("Domain:");
                JTextField tfDomain = new JTextField(28);
                tfDomain.setText(strDomain);

                JLabel lbRaw = new JLabel("Raw");
                JButton btnCopyRawToClipboard = new JButton("Copy to Clipboard");
                JTextArea taRaw = new JTextArea();
                taRaw.setLineWrap(true);
                taRaw.setWrapStyleWord(true);
                taRaw.setText(strRawCookie);
                JScrollPane spRaw= new JScrollPane(taRaw);

                JLabel lbJson = new JLabel("Json");
                JButton btnCopyJsonToClipboard = new JButton("Copy to Clipboard");
                JTextArea taJson = new JTextArea();
                taJson.setLineWrap(true);
                taJson.setWrapStyleWord(true);
                taJson.setEditable(false);
                taJson.setText(strJsonCookie);
                JScrollPane spJson= new JScrollPane(taJson);

                JLabel lbJs = new JLabel("JavaScript");
                JButton btnCopyJsToClipboard = new JButton("Copy to Clipboard");
                JTextArea taJs = new JTextArea();
                taJs.setLineWrap(true);
                taJs.setWrapStyleWord(true);
                taJs.setEditable(false);
                taJs.setText(strJsCookie);
                JScrollPane spJs= new JScrollPane(taJs);

                mPanel.add(lbDomain,new CustomizedGridBagConstraints(0,0,1,1).setFill(CustomizedGridBagConstraints.HORIZONTAL).setIpad(10, 10).setInsets(5));
                mPanel.add(tfDomain,new CustomizedGridBagConstraints(1,0,1,1).setFill(CustomizedGridBagConstraints.HORIZONTAL).setWeight(100, 0));
                mPanel.add(btnFreshen,new CustomizedGridBagConstraints(2,0,1,1).setFill(CustomizedGridBagConstraints.HORIZONTAL).setInsets(5));

                mPanel.add(lbRaw,new CustomizedGridBagConstraints(0,2,1,1).setFill(CustomizedGridBagConstraints.HORIZONTAL).setIpad(10, 10).setInsets(5));
                mPanel.add(btnCopyRawToClipboard,new CustomizedGridBagConstraints(2,2,1,1).setInsets(5));
                mPanel.add(spRaw,new CustomizedGridBagConstraints(0,3,3,5).setFill(CustomizedGridBagConstraints.BOTH).setIpad(100, 80).setWeight(100,0).setInsets(5));

                mPanel.add(lbJson,new CustomizedGridBagConstraints(0,9,1,1).setFill(CustomizedGridBagConstraints.HORIZONTAL).setIpad(10, 10).setInsets(5));
                mPanel.add(btnCopyJsonToClipboard,new CustomizedGridBagConstraints(2,9,1,1).setInsets(5));
                mPanel.add(spJson,new CustomizedGridBagConstraints(0,10,3,5).setFill(CustomizedGridBagConstraints.BOTH).setIpad(100, 80).setWeight(100,0).setInsets(5));

                mPanel.add(lbJs,new CustomizedGridBagConstraints(0,16,1,1).setFill(CustomizedGridBagConstraints.HORIZONTAL).setIpad(10, 10).setInsets(5));
                mPanel.add(btnCopyJsToClipboard,new CustomizedGridBagConstraints(2,16,1,1).setInsets(5));
                mPanel.add(spJs,new CustomizedGridBagConstraints(0,17,3,5).setFill(CustomizedGridBagConstraints.BOTH).setIpad(100, 80).setWeight(100,0).setInsets(5));

                CookieDialog.this.getContentPane().add(mPanel);

                btnCopyRawToClipboard.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        setSysClipboardText(taRaw.getText());
                    }
                });

                btnCopyJsonToClipboard.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        setSysClipboardText(taJson.getText());
                    }
                });

                btnCopyJsToClipboard.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        setSysClipboardText(taJs.getText());
                    }
                });

                btnFreshen.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        strRawCookie = taRaw.getText();
                        try{
                            strDomain = tfDomain.getText();
                            strJsonCookie = ToJson(strRawCookie);
                            strJsCookie = ToJs(strRawCookie);
                            taJson.setText(strJsonCookie);
                            taJs.setText(strJsCookie);
                        }catch (Exception e) {
                            JOptionPane.showMessageDialog(CookieDialog.this,e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                });
            }
        });
    }

    public String ToJson(String strCookie){
        String strJson = null;
        String[] listCookie = strCookie.split(";");
        List<Map> listJson = new ArrayList<>();
        for (String cookie:listCookie) {
            Map map = new HashMap();
            map.put("domain", strDomain);
            map.put("path","/");
            String[] c = cookie.split("=");
            map.put(c[0], c[1]);
            listJson.add(map);
        }
        strJson = JSON.toJSONString(listJson);
        return strJson;
    }

    private String ToJs(String strCookie){
        String strJs = null;
        String[] listCookie = strCookie.split(";");
        StringBuffer sb = new StringBuffer();
        for (String cookie:listCookie) {
            sb.append(String.format("document.cookie =\"%s\";",cookie));
        }
        strJs = sb.toString();
        return strJs;
    }

    public static void setSysClipboardText(String writeMe) {
        Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable tText = new StringSelection(writeMe);
        clip.setContents(tText, null);
    }
}