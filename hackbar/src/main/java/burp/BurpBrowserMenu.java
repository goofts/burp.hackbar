package burp;

import utils.CharSet;
import utils.HttpRequestResponseUtils;
import utils.CustomUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * BurpBrowserMenu
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpBrowserMenu implements IContextMenuFactory {
    private IBurpExtenderCallbacks mCallbacks;

    public BurpBrowserMenu(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> mMenus = new ArrayList<JMenuItem>();
        JMenuItem mOpenBrowser = new JMenuItem("open [web browser] on this");
        mMenus.add(mOpenBrowser);

        mOpenBrowser.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                try{
                    String browserPath = "default";
                    IHttpRequestResponse[] iReqResps = invocation.getSelectedMessages();

                    if (iReqResps == null ) {
                        return ;
                    }

                    if (iReqResps.length == 1) {
                        String selectedUrl = getSelectedStringByBurp(invocation);

                        if (selectedUrl.length()>10) {
                            CustomUtils.browserOpen(selectedUrl,browserPath);
                        }else {
                            String hosturl =mCallbacks.getHelpers().analyzeRequest(iReqResps[0]).getUrl().toString();
                            CustomUtils.browserOpen(hosturl,browserPath);
                        }
                    } else {
                        for(IHttpRequestResponse ReqResp:iReqResps) {
                            HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(mCallbacks.getHelpers());
                            URL targetShortUrl = httpRequestResponseUtils.getFullURL(ReqResp);
                            CustomUtils.browserOpen(targetShortUrl,browserPath);
                        }
                    }
                }
                catch (java.net.URISyntaxException e) {
                    e.printStackTrace();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        });

        return mMenus;
    }

    public static String getSelectedStringByBurp(final IContextMenuInvocation invocation){
        String result = "";

        IHttpRequestResponse[] messages = invocation.getSelectedMessages();

        if (messages == null ) {
            return result;
        }

        if (messages.length == 1) {
            IHttpRequestResponse message = messages[0];
            /////////////selected url/////////////////
            byte[] source = null;


            int context = invocation.getInvocationContext();
            if (context==IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                    || context ==IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                    || context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                    || context == IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS
                    || context == IContextMenuInvocation.CONTEXT_SEARCH_RESULTS
                    || context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE
                    || context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE) {
                source = message.getRequest();
            }else {
                source = message.getResponse();
            }

            int[] selectedIndex = invocation.getSelectionBounds();//当数据包中有中文或其他宽字符的时候，这里的返回值不正确。已报bug。
            //stdout.println(selectedIndex[0]+":"+selectedIndex[1]);
            //这里的index应该是字符串的index，进行选中操作时对象应该是字符文本内容，无论是一个中文还是一个字母，都是一个文本字符。这就是我们通常的文本操作啊，之前是想多了。
            //burp进行的byte和string之间的转换，没有考虑特定的编码，是一刀切的方式，所以将index用于byte序列上，就不能正确对应。

            if(source!=null && selectedIndex !=null && selectedIndex[1]-selectedIndex[0]>=3) {
                String originalCharSet = CharSet.getResponseCharset(source);
                String text;
                try {
                    text = new String(source,originalCharSet);
                }catch(Exception e) {
                    text = new String(source);
                }
                result = text.substring(selectedIndex[0], selectedIndex[1]);
                result = CustomUtils.getFullUrl(result,message);
            }
        }
        return result;
    }
}