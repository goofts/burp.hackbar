package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.List;
import javax.swing.JMenuItem;

import utils.HttpRequestResponseUtils;
import utils.MethodsUtils;

public class BurpChunkedEncodingMenu extends JMenuItem {
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;
    public IExtensionHelpers mHelpers;
    public HttpRequestResponseUtils httpRequestResponseUtils;
    private boolean useComment;
    private int chunkedLength;

    public BurpChunkedEncodingMenu(BurpExtender extender, IContextMenuInvocation invocation){
        try {
            this.mExtender = extender;
            this.mInvocation = invocation;
            this.mHelpers = extender.helpers;
            this.httpRequestResponseUtils = new HttpRequestResponseUtils(mHelpers);

            IHttpRequestResponse iReqResp = mInvocation.getSelectedMessages()[0];
            String chunked = httpRequestResponseUtils.getHeaderValueOf(true, iReqResp, "Transfer-Encoding");

            if (chunked == null || !chunked.equalsIgnoreCase("chunked") ) {
                this.setText("encode [chunked encoding] on this");
            }else {
                this.setText("decode [chunked decoding] on this");
            }

            this.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent event) {
                    IHttpRequestResponse iReqResp = mInvocation.getSelectedMessages()[0];
                    List<String> headers = httpRequestResponseUtils.getHeaderList(true, iReqResp);
                    byte[] body = httpRequestResponseUtils.getBody(true, iReqResp);

                    if (event.getActionCommand().equals("encode [chunked encoding] on this")) {
                        Iterator<String> iter = headers.iterator();
                        while (iter.hasNext()) {
                            if (((String)iter.next()).contains("Transfer-Encoding")) {
                                iter.remove();
                            }
                        }
                        headers.add("Transfer-Encoding: chunked");

                        try {
                            useComment =false;
                            if (mExtender.tableModel.getConfigValueByKey("Chunked-UseComment") != null) {
                                useComment = true;
                            }

                            chunkedLength =10;
                            String lenStr = mExtender.tableModel.getConfigValueByKey("Chunked-Length");
                            if (lenStr != null) {
                                chunkedLength = Integer.parseInt(lenStr);
                            }
                            body = MethodsUtils.encoding(body, chunkedLength,useComment);
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                    } else if (event.getActionCommand().equals("decode [chunked decoding] on this")) {
                        Iterator<String> iter = headers.iterator();
                        while (iter.hasNext()) {
                            if (((String)iter.next()).contains("Transfer-Encoding")) {
                                iter.remove();
                            }
                        }

                        try {
                            body = MethodsUtils.decoding(body);
                        } catch (UnsupportedEncodingException e) {
                            e.printStackTrace();
                        }
                    } else {
                        useComment =false;
                        if (mExtender.tableModel.getConfigValueByKey("Chunked-UseComment") != null) {
                            useComment = true;
                        }

                        chunkedLength =10;
                        String lenStr = mExtender.tableModel.getConfigValueByKey("Chunked-Length");
                        if (lenStr != null) {
                            chunkedLength = Integer.parseInt(lenStr);
                        }
                    }

                    byte[] newRequestBytes = mHelpers.buildHttpMessage(headers, body);
                    iReqResp.setRequest(newRequestBytes);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}