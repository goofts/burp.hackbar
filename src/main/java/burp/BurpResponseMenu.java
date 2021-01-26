package burp;

import ui.ResponseDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * BurpRespondeMenu
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpResponseMenu implements IContextMenuFactory {
    private IBurpExtenderCallbacks mCallbacks;

    public BurpResponseMenu(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> mMenus = new ArrayList<JMenuItem>();
        JMenuItem mRespondeDialog = new JMenuItem("open [response dialog] on this");
        mMenus.add(mRespondeDialog);

        mRespondeDialog.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                try{
                    ResponseDialog dialog = new ResponseDialog(mCallbacks, iReqResp);
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