package utils;

import java.io.File;
import javax.swing.filechooser.FileFilter;

/**
 * PcapFileFilter
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class PcapFileUtils extends FileFilter {
    @Override
    public String getDescription() {
        return "Packet Capture Files (*.pcap;*.pcapng files)";
    }

    @Override
    public boolean accept(File f) {
        return f.isDirectory() || f.getName().endsWith(".pcap") || f.getName().endsWith(".pcapng");
    }
}