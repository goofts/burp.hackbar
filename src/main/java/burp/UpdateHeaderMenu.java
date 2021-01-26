package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import config.HeaderEntry;
import utils.HttpRequestResponseUtils;
import utils.CookieUtils;

public class UpdateHeaderMenu extends JMenu {
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;

    public UpdateHeaderMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        try {
            if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {

                List<String> pHeaders = possibleHeaderNames(invocation);
                if(!pHeaders.isEmpty()) {
                    this.setText("Update Header");
                    for (String pheader:pHeaders) {
                        JMenuItem headerItem = new JMenuItem(pheader);
                        headerItem.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent event) {
                                IHttpRequestResponse[] selectedItems = mInvocation.getSelectedMessages();
                                IHttpRequestResponse messageInfo = selectedItems[0];
                                HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(BurpExtender.callbacks.getHelpers());
                                String shorturl = httpRequestResponseUtils.getShortURL(messageInfo).toString();
                                HeaderEntry urlAndtoken = CookieUtils.getLatestHeaderFromHistory(shorturl,pheader);

                                if (urlAndtoken !=null) {
                                    LinkedHashMap<String, String> headers = httpRequestResponseUtils.getHeaderMap(true,messageInfo);
                                    byte[] body = httpRequestResponseUtils.getBody(true,messageInfo);

                                    headers.put(pheader,urlAndtoken.getHeaderValue());
                                    List<String> headerList = httpRequestResponseUtils.headerMapToHeaderList(headers);

                                    byte[] newRequestBytes = mExtender.helpers.buildHttpMessage(headerList, body);
                                    selectedItems[0].setRequest(newRequestBytes);
                                }
                            }
                        });
                        this.add(headerItem);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public List<String> possibleHeaderNames(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
        HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(mExtender.helpers);
        LinkedHashMap<String, String> headers = httpRequestResponseUtils.getHeaderMap(true, selectedItems[0]);

        String tokenHeadersStr = mExtender.tableModel.getConfigValueByKey("tokenHeaders");

        List<String> ResultHeaders = new ArrayList<String>();
        
        if (tokenHeadersStr!= null && headers != null) {
            String[] tokenHeaders = tokenHeadersStr.split(",");
            List<String> keywords = Arrays.asList(tokenHeaders);
            Iterator<String> it = headers.keySet().iterator();
            while (it.hasNext()) {
                String item = it.next();
                if (containOneOfKeywords(item,keywords,false)) {
                    ResultHeaders.add(item);
                }
            }
        }

        return ResultHeaders;
    }

    public boolean containOneOfKeywords(String x,List<String> keywords,boolean isCaseSensitive) {
        for (String keyword:keywords) {
            if (isCaseSensitive == false) {
                x = x.toLowerCase();
                keyword = keyword.toLowerCase();
            }
            if (x.contains(keyword)){
                return true;
            }
        }
        return false;
    }
}