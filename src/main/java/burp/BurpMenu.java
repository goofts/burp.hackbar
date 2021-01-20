package burp;

import ui.CookieDlg;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Menu
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpMenu implements IContextMenuFactory {
    private final IExtensionHelpers m_helpers;
    private IBurpExtenderCallbacks m_callback;
    private PrintWriter stderr;
    public BurpMenu(IBurpExtenderCallbacks callbacks) {
        m_callback = callbacks;
        m_helpers = callbacks.getHelpers();
        stderr = new PrintWriter(m_callback.getStderr(),true);
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList();

        JMenuItem miCookiePorter = new JMenuItem("open cookie dialog on this");

        miCookiePorter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                try{
                    CookieDlg gui = new CookieDlg(m_callback,iReqResp);
                    m_callback.customizeUiComponent(gui);
                    gui.setVisible(true);
                }catch (Exception e) {
                    e.getMessage();
                }
            }
        });

        menus.add(miCookiePorter);
        return menus;
    }
}