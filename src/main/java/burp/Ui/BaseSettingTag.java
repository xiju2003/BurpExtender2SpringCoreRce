package burp.Ui;


import java.awt.*;
import java.util.List;
import java.util.ArrayList;
import javax.swing.*;

import burp.IBurpExtenderCallbacks;
import burp.Bootstrap.YamlReader;

public class BaseSettingTag {
    private JCheckBox isStartBox;
    private JTextField textField1;


    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs ) {
        JPanel baseSetting = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        this.input1_1(baseSetting, c);
        this.input1_2(baseSetting, c);
        this.input2_1(baseSetting, c);
        tabs.addTab("基本设置", baseSetting);
    }

    private void input1_1(JPanel baseSetting, GridBagConstraints c) {
        JLabel br_lbl_1_1 = new JLabel("基础设置(设置要扫描的域名，多个域名用';'分开)");
        br_lbl_1_1.setForeground(new Color(255, 89, 18));
        br_lbl_1_1.setFont(new Font("Serif", Font.PLAIN, br_lbl_1_1.getFont().getSize() + 2));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 1;
        baseSetting.add(br_lbl_1_1, c);
    }
    private void input1_2(JPanel baseSetting, GridBagConstraints c){
         textField1=new JTextField();
        textField1.setColumns(100);
        c.insets = new Insets(10, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 3;
        baseSetting.add(textField1, c);
    }


    private void input2_1(JPanel baseSetting, GridBagConstraints c) {
        this.isStartBox = new JCheckBox("插件-启动",false);
        this.isStartBox.setFont(new Font("Serif", Font.PLAIN, this.isStartBox.getFont().getSize()));
        c.insets = new Insets(5, 5, 5, 5);
        c.gridx = 0;
        c.gridy = 5;
        baseSetting.add(this.isStartBox, c);
    }

    public Boolean isStart() {
        return this.isStartBox.isSelected();
    }
    public String Whitelist(){
        return this.textField1.getText();
    }

}