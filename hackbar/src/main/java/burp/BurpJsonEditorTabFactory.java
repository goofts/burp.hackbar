package burp;

import ui.JsonEditorTab;

/**
 * BurpJsonEditorTab
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpJsonEditorTabFactory implements IMessageEditorTabFactory {
    private static IExtensionHelpers helpers;
    private static IBurpExtenderCallbacks callbacks;

    public static final String majorVersion = BurpExtender.mCallbacks.getBurpVersion()[1].replaceAll("[a-zA-Z]","");
    public static final String minorVersion = BurpExtender.mCallbacks.getBurpVersion()[2].replaceAll("[a-zA-Z]","");

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

    public BurpJsonEditorTabFactory(IMessageEditorController controller, boolean editable, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new JsonEditorTab(controller, editable, helpers, callbacks);
    }
}