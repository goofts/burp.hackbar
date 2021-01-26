package burp;

import config.ConfigEntry;
import utils.CustomUtils;
import utils.MethodsUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * BurpXXEPayloadMenu
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpXXEPayloadMenu extends JMenu {
    private static final long serialVersionUID = 1L;
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;
    public String[] customPayloadMenu;

    public BurpXXEPayloadMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        try {
            this.setText("add [xxe payload] on this");

            List<ConfigEntry> payload = extender.tableModel.getConfigByType(ConfigEntry.Config_XXE_Payload);
            Iterator<ConfigEntry> it = payload.iterator();
            List<String> tmp = new ArrayList<String>();
            while (it.hasNext()) {
                ConfigEntry item = it.next();
                tmp.add(item.getKey());
            }

            customPayloadMenu = tmp.toArray(new String[0]);
            MethodsUtils.addMenuItemAndListener(this, customPayloadMenu, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent event) {
                    IHttpRequestResponse iReqResp = mInvocation.getSelectedMessages()[0];
                    int[] selectedIndex = mInvocation.getSelectionBounds();
                    byte[] request = iReqResp.getRequest();
                    byte[] param = new byte[selectedIndex[1]-selectedIndex[0]];

                    System.arraycopy(request, selectedIndex[0], param, 0, selectedIndex[1]-selectedIndex[0]);
                    String selectString = new String(param);
                    String action = event.getActionCommand();

                    byte[] newRequest = CustomUtils.GetNewRequest(mExtender, request, selectString, selectedIndex, action);
                    iReqResp.setRequest(newRequest);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}