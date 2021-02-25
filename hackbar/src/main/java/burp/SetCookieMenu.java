package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;

import config.HeaderEntry;
import utils.HttpRequestResponseUtils;
import utils.CookieUtils;

public class SetCookieMenu extends JMenuItem {
    private static final long serialVersionUID = 1L;
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;

    public SetCookieMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        this.setText("Set Cookie");
        this.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                try{
                    HeaderEntry cookieEntry = CookieUtils.getLatestCookieFromSpeicified();

                    if (cookieEntry != null) {
                        IHttpRequestResponse[] messages = mInvocation.getSelectedMessages();
                        if (mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                            byte[] newRequest = CookieUtils.updateCookie(messages[0], cookieEntry.getHeaderValue());
                            try{
                                messages[0].setRequest(newRequest);
                            }catch (Exception e){
                                e.printStackTrace();
                            }
                            cookieEntry.setRequestUpdated(true);
                        }

                        for(IHttpRequestResponse message:messages) {
                            HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(mExtender.helpers);
                            String targetShortUrl = httpRequestResponseUtils.getShortURL(message).toString();
                            cookieEntry.setTargetUrl(targetShortUrl);
                            mExtender.config.getSetCookieMap().put(targetShortUrl, cookieEntry);
                        }
                        mExtender.config.setUsedCookie(cookieEntry);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}