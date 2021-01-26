package burp;

import ui.U2CEditorTab;

public class BurpU2CEditorTabFactory implements IMessageEditorTabFactory {
    private static IExtensionHelpers helpers;
    private static IBurpExtenderCallbacks callbacks;
    
    public static final String majorVersion = BurpExtender.callbacks.getBurpVersion()[1].replaceAll("[a-zA-Z]","");
    public static final String minorVersion = BurpExtender.callbacks.getBurpVersion()[2].replaceAll("[a-zA-Z]","");
    
    public static boolean needJSON() {
        try {
            float majorV = Float.parseFloat(majorVersion);
            float minorV = Float.parseFloat(minorVersion);
            if (majorV>=2020 && minorV >= 4.0f) {
                return false;
            }

            return true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return true;
        }
    }

    public BurpU2CEditorTabFactory(IMessageEditorController controller, boolean editable, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new U2CEditorTab(controller, editable, helpers, callbacks);
    }
}