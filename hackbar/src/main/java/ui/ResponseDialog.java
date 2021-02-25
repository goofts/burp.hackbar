package ui;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import utils.HttpRequestResponseUtils;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

public class ResponseDialog extends JDialog {
    private IHttpRequestResponse mReqResp;
    private IBurpExtenderCallbacks mCallbacks;
    private IExtensionHelpers mHelpers;
    private byte[] respBody;

    public ResponseDialog(IBurpExtenderCallbacks callbacks, IHttpRequestResponse reqresp) {
        this.mCallbacks = callbacks;
        this.mReqResp = reqresp;
        this.mHelpers = mCallbacks.getHelpers();
        this.respBody = (new HttpRequestResponseUtils(mHelpers)).getBody(false, reqresp);

        initialze();
    }

    private void initialze() {
        Toolkit toolkit = Toolkit.getDefaultToolkit();
        int x = (int) (toolkit.getScreenSize().getWidth() - this.getWidth()) / 2;
        int y = (int) (toolkit.getScreenSize().getHeight() - this.getHeight()) / 2;

        this.setTitle("response");
        this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        this.setLocationRelativeTo(null);
        this.setLayout(new BorderLayout());
        this.setLocation(x,y);
        this.setSize(450,300);

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JPanel mPanel = new JPanel();
                mPanel.setLayout(new BorderLayout());

                JButton btnChangDecode = new JButton("Change Decode");
                mPanel.add(btnChangDecode, BorderLayout.NORTH);

                JScrollPane scrollPane = new JScrollPane();
                scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
                JTextArea textArea = new JTextArea();
                textArea.setLineWrap(true);
                scrollPane.setViewportView(textArea);
                mPanel.add(scrollPane, BorderLayout.CENTER);

                JComboBox comboBox=new JComboBox();
                comboBox.addItem("UTF-8");
                comboBox.addItem("gbk");
                comboBox.addItem("gb2312");
                comboBox.addItem("GB18030");
                comboBox.addItem("Big5");
                comboBox.addItem("Unicode");
                mPanel.add(comboBox, BorderLayout.SOUTH);

                ResponseDialog.this.getContentPane().add(mPanel);

                btnChangDecode.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent event) {
                        try {
                            String encoding = (String)comboBox.getSelectedItem();
                            textArea.setText(new String(respBody, encoding));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });

                btnChangDecode.doClick();
            }
        });
    }
}