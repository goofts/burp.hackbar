package ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.google.common.base.Charsets;
import com.google.common.io.Files;
import com.google.gson.Gson;
import config.Config;
import config.ConfigEntry;
import model.ConfigTableModel;
import utils.JsonFileUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class ExtenderUIPanel extends JFrame {
    private static final long serialVersionUID = 1L;
  
    public Config config = new Config("default");

    private JPanel mContentPane;
    private JPanel mFooterPanel;
    private JLabel lblNewLabel_2;
    protected JScrollPane configPanel;
    private SortOrder sortedMethod;
    public ConfigTable table;
    public ConfigTableModel tableModel;
    private JButton RemoveButton;
    private JButton AddButton;
    private JSplitPane TargetSplitPane;
    public JLabel lblNewLabel_1;
    public JCheckBox chckbx_proxy;
    public JCheckBox chckbx_repeater;
    public JCheckBox chckbx_intruder;
    private JCheckBox chckbx_scope;

    private JButton RestoreButton;
    private JPanel panel_1;

    public ExtenderUIPanel() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setBounds(100, 100, 1174, 497);
        mContentPane =  new JPanel();
        mContentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        mContentPane.setLayout(new BorderLayout(0, 0));
        setContentPane(mContentPane);

        JPanel panel = new JPanel();
        mContentPane.add(panel, BorderLayout.NORTH);
        FlowLayout fl_panel = (FlowLayout) panel.getLayout();
        fl_panel.setAlignment(FlowLayout.LEFT);
        panel.setBorder(new LineBorder(new Color(0, 0, 0)));

        JLabel lblNewLabel = new JLabel("Requests that in : [");
        panel.add(lblNewLabel);

        chckbx_proxy = new JCheckBox("Proxy");
        chckbx_proxy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                config.setEnableStatus(checkEnabledFor());
            }
        });
        chckbx_proxy.setSelected(true);
        panel.add(chckbx_proxy);

        chckbx_repeater = new JCheckBox("Repeater");
        chckbx_repeater.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                config.setEnableStatus(checkEnabledFor());
            }
        });
        panel.add(chckbx_repeater);

        chckbx_intruder = new JCheckBox("Intruder");
        chckbx_intruder.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                config.setEnableStatus(checkEnabledFor());
            }
        });
        panel.add(chckbx_intruder);

        JLabel lblNewLabel_display = new JLabel("] AND [");
        panel.add(lblNewLabel_display);

        chckbx_scope = new JCheckBox("also In Scope");
        chckbx_scope.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                config.setOnlyForScope(chckbx_scope.isSelected());
            }
        });
        chckbx_scope.setSelected(false);
        panel.add(chckbx_scope);

        JLabel lblNewLabel_display1 = new JLabel("] will be auto updated");
        panel.add(lblNewLabel_display1);

        configPanel = new JScrollPane();
        configPanel.setViewportBorder(new LineBorder(new Color(0, 0, 0)));

        TargetSplitPane = new JSplitPane();
        TargetSplitPane.setResizeWeight(0.5);
        TargetSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
        mContentPane.add(TargetSplitPane, BorderLayout.CENTER);

        TargetSplitPane.setLeftComponent(configPanel);

        panel_1 = new JPanel();
        panel_1.setBorder(new LineBorder(new Color(0, 0, 0)));
        TargetSplitPane.setRightComponent(panel_1);
        panel_1.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

        
        AddButton = new JButton("Add New Line");
        AddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                tableModel.addNewConfigEntry(new ConfigEntry("","","",true));
                saveConfigToBurp();
            }
        });
        panel_1.add(AddButton);

        RemoveButton = new JButton("Remove Selected Line");
        panel_1.add(RemoveButton);
        RemoveButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                int[] rowindexs = table.getSelectedModelRows();
                tableModel.removeRows(rowindexs);
                saveConfigToBurp();
            }
        });
        
        
        JButton btnSave = new JButton("Save Config");
        btnSave.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                saveConfigToBurp();
            }});
        btnSave.setToolTipText("Save Config To Extension Setting");
        panel_1.add(btnSave);
        
        panel_1.add(new Label(" |"));
        
        JButton btnOpen = new JButton("Import Config(Override)");
        btnOpen.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                JFileChooser fc=new JFileChooser();
                JsonFileUtils jsonFile = new JsonFileUtils(); //excel过滤器
                fc.addChoosableFileFilter(jsonFile);
                fc.setFileFilter(jsonFile);
                fc.setDialogTitle("Chose hackbar config File");
                fc.setDialogType(JFileChooser.CUSTOM_DIALOG);
                if(fc.showOpenDialog(null)==JFileChooser.APPROVE_OPTION){
                    try {
                        File file=fc.getSelectedFile();
                        String contents = Files.toString(file, Charsets.UTF_8);
                        config = new Gson().fromJson(contents, Config.class);
                        showToUI(config);

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                saveConfigToBurp();
            }
        });
        btnOpen.setToolTipText("Load Config File");
        panel_1.add(btnOpen);
        
        JButton btnImport = new JButton("Import Config(Combine)");
        btnImport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                
                JFileChooser fc = new JFileChooser();
                JsonFileUtils jsonFile = new JsonFileUtils(); //过滤器
                fc.addChoosableFileFilter(jsonFile);
                fc.setFileFilter(jsonFile);
                fc.setDialogTitle("Chose hackbar config File");
                fc.setDialogType(JFileChooser.CUSTOM_DIALOG);
                if(fc.showOpenDialog(null)==JFileChooser.APPROVE_OPTION){
                    try {
                        File file=fc.getSelectedFile();
                        String contents = Files.toString(file, Charsets.UTF_8);
                        config = new Gson().fromJson(contents, Config.class);
                        List<String> newEntries = config.getStringConfigEntries();
                        List<String> newEntryNames = new ArrayList<String>(); 
                        for (String config:newEntries) {
                            ConfigEntry entry  = new ConfigEntry().FromJson(config);
                            newEntryNames.add(entry.getKey());
                        }
                        
                        List<ConfigEntry> currentEntries = tableModel.getConfigEntries();
                        
                        for (ConfigEntry config:currentEntries) {
                            if (!newEntryNames.contains(config.getKey())){
                                newEntries.add(config.ToJson());
                            }
                        }
                        showToUI(config);

                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                
                saveConfigToBurp();
            }});
        btnImport.setToolTipText("Combine your configration with current");
        panel_1.add(btnImport);

        JButton btnExport = new JButton("Export Config");
        btnExport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                saveConfigToBurp();
                saveDialog();
            }});
        btnExport.setToolTipText("Export Config To A File");
        panel_1.add(btnExport);

        RestoreButton = new JButton("Restore Defaults");
        RestoreButton.setToolTipText("Restore all config to default!");
        RestoreButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                int user_input = JOptionPane.showConfirmDialog(null, "Are you sure to restore all config to default?","Restore Config",JOptionPane.YES_NO_OPTION);
                if (JOptionPane.YES_OPTION == user_input) {
                    showToUI(new Config("Default").FromJson(initConfig()));
                    saveConfigToBurp();
                }else {
                    
                }
            }
        });
        panel_1.add(RestoreButton);
        
        JButton testButton = new JButton("test");
        testButton.setToolTipText("test");
        testButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                
            }
        });

        mFooterPanel = new JPanel();
        FlowLayout fl_FooterPanel = (FlowLayout) mFooterPanel.getLayout();
        fl_FooterPanel.setAlignment(FlowLayout.LEFT);
        mContentPane.add(mFooterPanel, BorderLayout.SOUTH);

        lblNewLabel_2 = new JLabel(BurpExtender.extensionName +"    https://github.com/bit4woo/knife");
        lblNewLabel_2.setFont(new Font("宋体", Font.BOLD, 12));
        lblNewLabel_2.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                try {
                    URI uri = new URI("https://github.com/bit4woo/knife");
                    Desktop desktop = Desktop.getDesktop();
                    if(Desktop.isDesktopSupported()&&desktop.isSupported(Desktop.Action.BROWSE)){
                        desktop.browse(uri);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            @Override
            public void mouseEntered(MouseEvent event) {
                lblNewLabel_2.setForeground(Color.BLUE);
            }
            @Override
            public void mouseExited(MouseEvent event) {
                lblNewLabel_2.setForeground(Color.BLACK);
            }
        });
        mFooterPanel.add(lblNewLabel_2);
    }

    public void showToUI(Config config) {
        tableModel = table.getModel();
        tableModel.setConfigEntries(new ArrayList<ConfigEntry>());
        
        for (String stringEntry:config.getStringConfigEntries()) {
            ConfigEntry entry  = new ConfigEntry().FromJson(stringEntry);
            tableModel.addNewConfigEntry(entry);
        }
        table.setupTypeColumn();// must setup again when data cleaned

        if (IBurpExtenderCallbacks.TOOL_INTRUDER ==(config.getEnableStatus() & IBurpExtenderCallbacks.TOOL_INTRUDER)) {
            chckbx_intruder.setSelected(true);
        }else {
            chckbx_intruder.setSelected(false);
        }
        if (IBurpExtenderCallbacks.TOOL_PROXY ==(config.getEnableStatus() & IBurpExtenderCallbacks.TOOL_PROXY)) {
            chckbx_proxy.setSelected(true);
        }else {
            chckbx_proxy.setSelected(false);
        }
        if (IBurpExtenderCallbacks.TOOL_REPEATER ==(config.getEnableStatus() & IBurpExtenderCallbacks.TOOL_REPEATER)) {
            chckbx_repeater.setSelected(true);
        }else {
            chckbx_repeater.setSelected(false);
        }
        chckbx_scope.setSelected(config.isOnlyForScope());
    }

    public String getAllConfig() {
        config.setStringConfigEntries(tableModel.getConfigJsons());
        return config.ToJson();
    }
    
    public void saveConfigToBurp() {
        BurpExtender.mCallbacks.saveExtensionSetting("hackbarconfig", getAllConfig());
    }

    public int checkEnabledFor(){
        //get values that should enable this extender for which Component.
        int status = 0;
        if (chckbx_intruder.isSelected()){
            status += IBurpExtenderCallbacks.TOOL_INTRUDER;
        }
        if(chckbx_proxy.isSelected()){
            status += IBurpExtenderCallbacks.TOOL_PROXY;
        }
        if(chckbx_repeater.isSelected()){
            status += IBurpExtenderCallbacks.TOOL_REPEATER;
        }
        return status;
    }


    public void saveDialog() {
        JFileChooser fc=new JFileChooser();
        JsonFileUtils jsonFile = new JsonFileUtils(); //excel过滤器
        fc.addChoosableFileFilter(jsonFile);
        fc.setFileFilter(jsonFile);
        fc.setDialogTitle("Save Config To A File:");
        fc.setDialogType(JFileChooser.SAVE_DIALOG);
        if(fc.showSaveDialog(null)==JFileChooser.APPROVE_OPTION){
            File file=fc.getSelectedFile();

            if(!(file.getName().toLowerCase().endsWith(".json"))){
                file=new File(fc.getCurrentDirectory(),file.getName()+".json");
            }

            String content= getAllConfig();
            try{
                if(file.exists()){
                    int result = JOptionPane.showConfirmDialog(null,"Are you sure to overwrite this file ?");
                    if (result == JOptionPane.YES_OPTION) {
                        file.createNewFile();
                    }else {
                        return;
                    }
                }else {
                    file.createNewFile();
                }

                Files.write(content.getBytes(), file);
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }
    
    public String initConfig() {
        // need to override
        return null;
    }
}