package utils;

import javax.swing.filechooser.FileFilter;
import java.io.File;

/**
 * JsonFileUtils
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class JsonFileUtils extends FileFilter {
    public String getDescription() {
        return "*.json";
    }

    public boolean accept(File file) {
        String name = file.getName();
        return file.isDirectory() || name.toLowerCase().endsWith(".json");
    }
}