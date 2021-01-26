package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;

import config.HeaderEntry;
import utils.HttpRequestResponseUtils;
import utils.CookieUtils;

public class UpdateCookieMenu extends JMenuItem {
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;

    public UpdateCookieMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        if (mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            this.setText("Update Cookie");
            this.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent event) {
                    try {
                        //stdout.println("UpdateCookieAction called");
                        IHttpRequestResponse[] selectedItems = mInvocation.getSelectedMessages();

                        HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(mExtender.helpers);
                        String sourceshorturl = httpRequestResponseUtils.getShortURL(selectedItems[0]).toString();
                        HeaderEntry latestCookie = CookieUtils.getLatestCookieFromHistory(sourceshorturl);//自行查找一次

                        //通过弹窗交互 获取Cookie
                        int time = 0;
                        while (!isVaildCookie(latestCookie) && time <2) {
                            latestCookie = CookieUtils.getLatestCookieFromSpeicified();
                            time++;
                        }

                        if (isVaildCookie(latestCookie)) {
                            String latestCookieValue = latestCookie.getHeaderValue();
                            sourceshorturl = latestCookie.getHeaderSource();

                            byte[] newRequest = CookieUtils.updateCookie(selectedItems[0], latestCookieValue);
                            try{
                                selectedItems[0].setRequest(newRequest);
                            }catch (Exception e){
                                e.printStackTrace();
                                //stderr.print(e.getMessage());
                                //这是个bug，请求包实际还是被修改了，但是就是报这个错误！
                                //当在proxy中拦截状态下更新请求包的时候，总是会报这个假错误！
                                //"java.lang.UnsupportedOperationException: Request has already been issued"
                            }

                            if (sourceshorturl.startsWith("http")) {
                                mExtender.config.setUsedCookie(latestCookie);
                            }
                        }else {
                            //do nothing
                        }
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            });
        }
    }

    public boolean isVaildCookie(HeaderEntry urlAndCookieString) {
        if (urlAndCookieString == null) {
            return false;
        }
        String currentCookie = new HttpRequestResponseUtils(mExtender.helpers).getHeaderValueOf(true,mInvocation.getSelectedMessages()[0],"Cookie");
        String foundCookie = urlAndCookieString.getHeaderValue();
        if (foundCookie.equalsIgnoreCase(currentCookie)) {
            return false;
        }
        return true;
    }
}