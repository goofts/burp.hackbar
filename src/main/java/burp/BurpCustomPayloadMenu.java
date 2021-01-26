package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JMenu;

import utils.MethodsUtils;
import config.ConfigEntry;
import utils.CustomUtils;

public class BurpCustomPayloadMenu extends JMenu {
    private static final long serialVersionUID = 1L;
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;
    public String[] customPayloadMenu;

    public BurpCustomPayloadMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        try {
            this.setText("add [custom payload] on this");

            List<ConfigEntry> payload = extender.tableModel.getConfigByType(ConfigEntry.Config_Custom_Payload);
            List<ConfigEntry> payloadBase64 = extender.tableModel.getConfigByType(ConfigEntry.Config_Custom_Payload_Base64);
            payload.addAll(payloadBase64);
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