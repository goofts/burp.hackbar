package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;

import config.HeaderEntry;
import utils.HttpRequestResponseUtils;

public class SetCookieWithHistoryMenu extends JMenuItem {
    private static final long serialVersionUID = 1L;
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;

    public SetCookieWithHistoryMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        try {
            HeaderEntry cookieToSetHistory = extender.config.getUsedCookie();
            if (cookieToSetHistory != null) {
                String targetUrl = cookieToSetHistory.getTargetUrl();
                String originUrl = cookieToSetHistory.getHeaderSource();
                String cookieValue = cookieToSetHistory.getHeaderValue();

                this.setText(String.format("Set Cookie (%s)",originUrl));
                this.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        HeaderEntry cookieToSetHistory = extender.config.getUsedCookie();

                        try{
                            IHttpRequestResponse[] messages = mInvocation.getSelectedMessages();
                            for(IHttpRequestResponse message:messages) {
                                HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(mExtender.helpers);
                                String targetShortUrl = httpRequestResponseUtils.getShortURL(message).toString();
                                cookieToSetHistory.setTargetUrl(targetShortUrl);
                                extender.config.getSetCookieMap().put(targetShortUrl, cookieToSetHistory);
                                //这个设置，让proxy处理它的响应包，shortUrl是新的target
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}