package ui;

import burp.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.text.StringEscapeUtils;
import utils.HttpRequestResponseUtils;
import burp.BurpU2CEditorTabFactory;

import java.awt.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * U2CEditorTab
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class U2CEditorTab implements IMessageEditorTab {
    private ITextEditor txtInput;
    private byte[] originContent;
    private byte[] displayContent = "nothing to show".getBytes();
    private static IExtensionHelpers helpers;

    public U2CEditorTab(IMessageEditorController controller, boolean editable, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        txtInput = callbacks.createTextEditor();
        txtInput.setEditable(editable);
        U2CEditorTab.helpers = helpers;
    }

    @Override
    public String getTabCaption() {
        return "u2c editor";
    }

    @Override
    public Component getUiComponent() {
        return txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        if (BurpU2CEditorTabFactory.needJSON() && isJSON(content, isRequest)) {
            return true;
        }

        String contentStr = new String(content);
        if (needtoconvert(contentStr)) {
            return true;
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        try {
            if (content == null) {
                txtInput.setText(displayContent);
                return;
            }

            originContent = content;
            if (isJSON(content, isRequest)) {
                try {
                    HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(helpers);
                    byte[] body = httpRequestResponseUtils.getBody(isRequest, content);
                    List<String> headers = httpRequestResponseUtils.getHeaderList(isRequest, content);

                    displayContent = helpers.buildHttpMessage(headers, beauty(new String(body)).getBytes());
                    txtInput.setText(displayContent);
                    return;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            int i = 0;
            String contentStr = new String(content);
            while (needtoconvert(contentStr) && i <= 3) {
                contentStr = StringEscapeUtils.unescapeJava(contentStr);
                i++;
            }

            if (i > 0) {
                displayContent = contentStr.getBytes();
                txtInput.setText(displayContent);
                return;
            }
        } catch (Exception e) {
            displayContent = e.getMessage().getBytes();
            e.printStackTrace();
        } finally {
            txtInput.setText(displayContent);
        }
    }

    @Override
    public byte[] getMessage() {
        return originContent;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return txtInput.getSelectedText();
    }


    public static boolean isJSON(byte[] content, boolean isRequest) {
        if (isRequest) {
            IRequestInfo requestInfo = helpers.analyzeRequest(content);
            return requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON;
        } else {
            IResponseInfo responseInfo = helpers.analyzeResponse(content);
            return responseInfo.getInferredMimeType().equals("JSON");
        }
    }

    public static String beauty(String inputJson) {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
        JsonParser jp = new JsonParser();
        JsonElement je = jp.parse(inputJson);
        return gson.toJson(je);
    }

    public static boolean needtoconvert(String str) {
        Pattern pattern = Pattern.compile("(\\\\u(\\p{XDigit}{4}))");
        Matcher matcher = pattern.matcher(str.toLowerCase());

        if (matcher.find()) {
            return true;
        } else {
            return false;
        }
    }
}