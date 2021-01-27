package ui;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * ProgressDialog
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class ProgressDialog extends JDialog {
    private static final long serialVersionUID = 34345435L;

    private JProgressBar progressBar;
    private JLabel label;

    public ProgressDialog(JFrame parent, String title, String message) {
        super(parent, title, true);
        if (parent != null) {
            Dimension parentSize = parent.getSize();
            Point p = parent.getLocation();
            setLocation(p.x + parentSize.width / 4, p.y + parentSize.height / 4);
        }
        JPanel messagePane = new JPanel();
        label = new JLabel(message);
        messagePane.add(label);
        getContentPane().add(messagePane);

        JPanel progressPane = new JPanel();
        progressBar = new JProgressBar(0, 100);
        progressBar.setIndeterminate(true);
        progressBar.setPreferredSize(new Dimension(250, 20));
        progressBar.setVisible(true);
        progressPane.add(progressBar);

        getContentPane().add(progressPane, BorderLayout.SOUTH);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        pack();
    }

    public void setCurrentFile(File file) {
        label.setText("Loading " + file.getName() + "...");
    }
}