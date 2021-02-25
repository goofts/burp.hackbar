package burp;

import config.ConfigEntry;
import utils.MethodsUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * XssPayloadMenu
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpXssPayloadMenu extends JMenu {
    private static final long serialVersionUID = 1L;
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;
    public String[] customPayloadMenu;
    public String[][] customSubPayloadMenu;

    public BurpXssPayloadMenu(BurpExtender extender, IContextMenuInvocation invocation){
        try {
            this.setText("add [xss payload] on this");
            this.mExtender = extender;
            this.mInvocation = invocation;

            List<ConfigEntry> payload = extender.tableModel.getConfigByType(ConfigEntry.Config_Xss_Payload);
            Iterator<ConfigEntry> it = payload.iterator();
            List<String> tmpKey = new ArrayList<String>();
            List<String[]> tmpValue = new ArrayList<String[]>();
            while (it.hasNext()) {
                ConfigEntry item = it.next();
                tmpKey.add(item.getKey());
                tmpValue.add(item.getValue().split(", "));
            }

            customPayloadMenu = tmpKey.toArray(new String[0]);
            customSubPayloadMenu = tmpValue.toArray(new String[0][0]);
            MethodsUtils.createMultipleMenu(this, customPayloadMenu, customSubPayloadMenu, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent event) {
                    IHttpRequestResponse iReqResp = mInvocation.getSelectedMessages()[0];
                    int[] selectedIndex = mInvocation.getSelectionBounds();
                    byte[] request = iReqResp.getRequest();
                    byte[] param = new byte[selectedIndex[1]-selectedIndex[0]];

                    System.arraycopy(request, selectedIndex[0], param, 0, selectedIndex[1]-selectedIndex[0]);
                    String selectString = new String(param);
                    String action = event.getActionCommand();
                    byte[] newRequest = addXssPayload(request, selectString, action, selectedIndex);
                    iReqResp.setRequest(newRequest);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] addXssPayload(byte[] request, String selectedString, String action, int[] selectedIndex){
        selectedString = action;

        return MethodsUtils.doModifyRequest(request, selectedIndex, selectedString.getBytes());
    }
}