package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import config.HeaderEntry;
import utils.CookieUtils;

public class UpdateCookieWithHistoryMenu extends JMenuItem {
    public BurpExtender mExtender;
    public IContextMenuInvocation mInvocation;
    //JMenuItem vs. JMenu
    public UpdateCookieWithHistoryMenu(BurpExtender extender, IContextMenuInvocation invocation){
        this.mExtender = extender;
        this.mInvocation = invocation;

        try {
            if (mInvocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {

                HeaderEntry usedCookie = mExtender.config.getUsedCookie();
                if (usedCookie != null) {
                    String fromUrl = usedCookie.getHeaderSource();
                    String cookieValue = usedCookie.getHeaderValue();
                    this.setText("Update Cookie ("+fromUrl+")");
                    this.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent event) {
                            IHttpRequestResponse[] selectedItems = mInvocation.getSelectedMessages();
                            byte selectedInvocationContext = mInvocation.getInvocationContext();
                            if (cookieValue !=null) {
                                byte[] newRequestBytes = CookieUtils.updateCookie(selectedItems[0],cookieValue);

                                if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
                                    selectedItems[0].setRequest(newRequestBytes);
                                }
                            }
                        }
                    });
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}