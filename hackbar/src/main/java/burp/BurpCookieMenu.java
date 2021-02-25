package burp;

import ui.CookieDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * BurpCookieMenu
 * add cookie dialog menu
 *
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpCookieMenu implements IContextMenuFactory {
    private IBurpExtenderCallbacks mCallbacks;

    public BurpCookieMenu(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> mMenus = new ArrayList<JMenuItem>();
        JMenuItem mCookieDialog = new JMenuItem("open [cookie dialog] on this");
        mMenus.add(mCookieDialog);

        mCookieDialog.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                try{
                    CookieDialog dialog = new CookieDialog(mCallbacks, iReqResp);
                    mCallbacks.customizeUiComponent(dialog);
                    dialog.setVisible(true);
                }catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        return mMenus;
    }
}