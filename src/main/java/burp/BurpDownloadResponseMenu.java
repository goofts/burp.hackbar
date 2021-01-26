package burp;

import org.apache.commons.io.FileUtils;
import utils.HttpRequestResponseUtils;
import utils.CustomUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * BurpDownloadResponseMenu
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpDownloadResponseMenu implements IContextMenuFactory {
    private IBurpExtenderCallbacks mCallbacks;

    public BurpDownloadResponseMenu(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> mMenus = new ArrayList<JMenuItem>();
        JMenuItem mCookieDialog = new JMenuItem("download [response body] for this");
        mMenus.add(mCookieDialog);

        mCookieDialog.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                HttpRequestResponseUtils httpRequestResponseUtils = new HttpRequestResponseUtils(mCallbacks.getHelpers());
                try {
                    String urlfilename = httpRequestResponseUtils.getFullURL(iReqResp).getFile();
                    byte[] respBody = httpRequestResponseUtils.getBody(false, iReqResp);
                    File downloadFile = CustomUtils.saveFile(urlfilename);

                    if (downloadFile != null) {
                        FileUtils.writeByteArrayToFile(downloadFile, respBody);
                    }
                }catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        return mMenus;
    }
}