package burp;

import pcap.reconst.ex.PcapException;
import pcap.reconst.tcp.StatusHandle;
import ui.ProgressDialog;
import utils.HttpReconstructorUtils;
import utils.PcapFileUtils;
import utils.PcapngFileUtils;

import javax.swing.*;

import java.awt.event.ActionEvent;
import java.io.File;
import java.io.IOException;

/**
 * OpenPcapFileMenuAction
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class BurpOpenPcapFileMenu extends AbstractAction {
    private static final long serialVersionUID = 5003331249971440291L;
    private static final String PREV_PCAP_DIR = "PREV_PCAP_DIR";
    private IBurpExtenderCallbacks mCallbacks;
    private final JFileChooser fc = new JFileChooser();

    public BurpOpenPcapFileMenu(IBurpExtenderCallbacks callbacks) {
        this.mCallbacks = callbacks;

        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        fc.setMultiSelectionEnabled(true);
        fc.setFileFilter(new PcapFileUtils());

        String previousDir = callbacks.loadExtensionSetting(PREV_PCAP_DIR);
        if (previousDir != null) {
            File previousDirFileObj = new File(previousDir);
            fc.setCurrentDirectory(previousDirFileObj);
        }

        setEnabled(true);
        putValue("Name", "open [pcap file] on this");
    }

    public void actionPerformed(ActionEvent event) {
        int returnVal = fc.showOpenDialog(null);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            new Thread(new Runnable() {
                public void run() {
                    File[] files = fc.getSelectedFiles();

                    final ProgressDialog progressWindow = new ProgressDialog(
                            new JFrame(), "open [pcap file] on this", "preparing...");

                    final StatusHandle statusHandle = new StatusHandle();

                    //New thread for the modal dialog, as setVisible is blocking
                    new Thread(new Runnable() {
                        public void run() {
                            progressWindow.setLocationRelativeTo(null);
                            progressWindow.setVisible(true);
                            statusHandle.cancel();
                        }}).start();

                    for (File file : files)
                    {
                        boolean shouldDelete = false;
                        mCallbacks.saveExtensionSetting(PREV_PCAP_DIR, file.getParent());

                        progressWindow.setCurrentFile(file);

                        if (file.getAbsolutePath().endsWith(".pcapng"))
                        {
                            try
                            {
                                File tempFile = File.createTempFile("burp", ".pcap");
                                PcapngFileUtils.convert(file, tempFile);
                                file = tempFile;
                                shouldDelete = true;
                            }
                            catch (IOException ioe)
                            {
                                JOptionPane.showMessageDialog(null,
                                        ioe.getLocalizedMessage(),
                                        "Pcapng Conversion Exception",
                                        JOptionPane.ERROR_MESSAGE);
                                break;
                            }
                        }

                        try {
                            HttpReconstructorUtils.loadPcap(mCallbacks, file, statusHandle);
                        }
                        catch(PcapException pce)
                        {
                            JOptionPane.showMessageDialog(null,
                                    pce.getLocalizedMessage(),
                                    "Pcap Exception",
                                    JOptionPane.ERROR_MESSAGE);
                        }
                        catch(UnsatisfiedLinkError ule)
                        {
                            // write a message to the Burp alerts tab
                            mCallbacks.issueAlert("Unable to load jNetPcap library from java.library.path");
                            mCallbacks.issueAlert("java.library.path is "+ System.getProperty("java.library.path"));
                            mCallbacks.issueAlert("Visit https://github.com/neonbunny/pcap-reconst/tree/master/lib for available libraries.");
                        }
                        finally
                        {
                            if (shouldDelete)
                            {
                                file.delete();
                            }
                        }
                    }

                    progressWindow.dispose();
                }}).start();
        }
    }
}