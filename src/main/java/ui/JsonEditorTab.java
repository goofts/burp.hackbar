package ui;

import java.awt.Component;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ITextEditor;
import utils.HttpRequestResponseUtils;

public class JsonEditorTab implements IMessageEditorTab, IMessageEditorTabFactory {
    private ITextEditor txtInput;
    private byte[] originContent;
    private IExtensionHelpers helpers;
    private boolean workfine = true;

    public JsonEditorTab(IMessageEditorController controller, boolean editable, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        txtInput = callbacks.createTextEditor();
        txtInput.setEditable(editable);
        this.helpers = helpers;
    }

    @Override
    public String getTabCaption()
    {
        return "JSON";
    }

    @Override
    public Component getUiComponent()
    {
        return txtInput.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        try {
            if (!workfine) {//当JSON解析失败时，还是要尝试显示U2C
                return false;
            }
            
            if (content== null) {
                return false;
            }
            originContent = content;
            if (isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);
                return requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON;
            } else {
                IResponseInfo responseInfo = helpers.analyzeResponse(content);
                return responseInfo.getInferredMimeType().equals("JSON");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        try {
            if (content == null) {
                // clear our display
                txtInput.setText("none".getBytes());
                txtInput.setEditable(false);
            } else {
                //Get only the JSON part of the content
                HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(helpers);
                byte[] body = httpRequestResponseUtils.getBody(isRequest, content);
                List<String> headers = httpRequestResponseUtils.getHeaderList(isRequest, content);

                byte[] newContet = helpers.buildHttpMessage(headers, beauty(new String(body)).getBytes());
                //newContet = CharSet.covertCharSetToByte(newContet);

                txtInput.setText(newContet);
            }
        } catch (Exception e) {
            workfine = false;
            txtInput.setText(e.getStackTrace().toString().getBytes());
        }
    }
    
    public static String beauty(String inputJson) {
        //Take the input, determine request/response, parse as json, then print prettily.
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
        JsonParser jp = new JsonParser();
        JsonElement je = jp.parse(inputJson);
        return gson.toJson(je);
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

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new JsonEditorTab(null, false, BurpExtender.mCallbacks.getHelpers(), BurpExtender.mCallbacks);
    }
}