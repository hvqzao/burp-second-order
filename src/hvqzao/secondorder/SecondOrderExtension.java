// Token Second Order Extension, (c) 2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.secondorder;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.ITab;
import java.awt.Component;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

public class SecondOrderExtension implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener {

    private static IBurpExtenderCallbacks callbacks;
    //private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    //private JFrame burpFrame;
    private ImageIcon iconHelp;
    private SecondOrderOptions optionsPane;
    private final ArrayList<Rule> rule = new ArrayList<>();
    private RuleTableModel ruleTableModel;
    private final List<JMenuItem> contextMenu = new ArrayList<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        SecondOrderExtension.callbacks = callbacks;
        // obtain an extension helpers object
        //helpers = callbacks.getHelpers();
        // set extension name
        callbacks.setExtensionName("Second Order");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            // images
            iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/secondorder/resources/panel_help.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            ImageIcon iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/secondorder/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
            Dimension iconDimension = new Dimension(24, 24);
            //
            // extension tab
            optionsPane = new SecondOrderOptions();
            callbacks.customizeUiComponent(optionsPane);
            //
            JButton optionsHelp = optionsPane.getOptionsHelp();
            optionsHelp.setIcon(iconHelp);
            optionsHelp.setEnabled(false);
            callbacks.customizeUiComponent(optionsHelp);
            //
            JButton optionsDefaults = optionsPane.getOptionsDefaults();
            optionsDefaults.setIcon(iconDefaults);
            optionsDefaults.setEnabled(false);
            callbacks.customizeUiComponent(optionsDefaults);
            //
            JTable tokenTable = optionsPane.getRuleTable();
            // table
            ruleTableModel = new RuleTableModel();
            //tokenTableSorter = new TableRowSorter<>(tokenTableModel);
            tokenTable.setModel(ruleTableModel);
            // optionsTokensTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            // optionsTokensTable.getTableHeader().setReorderingAllowed(true);
            tokenTable.setAutoCreateRowSorter(true);
            //optionsTokensTable.setRowSorter(tokenTableSorter);
            for (int i = 0; i < ruleTableModel.getColumnCount(); i++) {
                TableColumn column = tokenTable.getColumnModel().getColumn(i);
                column.setMinWidth(20);
                column.setPreferredWidth(ruleTableModel.getPreferredWidth(i));
            }
            callbacks.customizeUiComponent(tokenTable);

            // options tab wrapper
            optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            optionsTab.setFocusable(false);
            //
            JSplitPane optionsRuleTableSplitPane = optionsPane.getRuleTableSplitPane();
            optionsRuleTableSplitPane.setDividerSize(10);
            //optionsTokensTableSplitPane.setContinuousLayout(true);
            optionsRuleTableSplitPane.setUI(new GlyphSplitPaneUI(optionsPane.getBackground())); // each need separate instance
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(SecondOrderExtension.this);
            // context menu
            JMenu menu = new JMenu("Second Order");
            JMenuItem addRequestMenuItem = new JMenuItem("Add request to extension");
            menu.add(addRequestMenuItem);
            contextMenu.add(menu);
            callbacks.registerContextMenuFactory(SecondOrderExtension.this);
            // get burp frame and tabbed pane handler
            //burpFrame = (JFrame) SwingUtilities.getWindowAncestor(optionsTab);
            //
            int row = rule.size();
            rule.add(new Rule());
            rule.add(new Rule());
            rule.add(new Rule());
            ruleTableModel.fireTableRowsInserted(row, row);            
            //
            //callbacks.printOutput("Loaded.");
        });
    }

    //
    // implement ITab
    //
    @Override
    public String getTabCaption() {
        return "Second";
    }

    @Override
    public Component getUiComponent() {
        return optionsTab;
    }

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // TODO
    }

    //
    // implement IContextMenuFactory
    //
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return contextMenu;
    }

    //
    // misc
    //
    class Rule {

    }

    class RuleTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return rule.size();
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return true;
                default:
                    return false;
            }
        }
        
        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "Active";
                case 1:
                    return "Method";
                case 2:
                    return "URL";
                case 3:
                    return "Comment";
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return Boolean.class;
                default:
                    return String.class;
            }
        }
        
        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
             switch (columnIndex) {
                case 0:
                    return false;
                default:
                    return "";
            }           
        }

        public int getPreferredWidth(int column) {
            switch (column) {
                case 0:
                    return 80;
                case 1:
                    return 80;
                case 2:
                    return 180;
                case 3:
                    return 120;
                default:
                    return 80;
            }
        }

    }
}
