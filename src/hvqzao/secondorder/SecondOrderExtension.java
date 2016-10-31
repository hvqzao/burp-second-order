// Token Second Order Extension, (c) 2016 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.secondorder;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.ITab;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
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
    private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    //private JFrame burpFrame;
    private ImageIcon iconHelp;
    private SecondOrderOptions optionsPane;
    private final ArrayList<Rule> rules = new ArrayList<>();
    private RuleTableModel ruleTableModel;
    private final List<JMenuItem> contextMenu = new ArrayList<>();
    private IContextMenuInvocation invocation;
    private JMenu menu;
    private JMenuItem addRequestMenuItem;
    private Rule active;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        SecondOrderExtension.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
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
            JTable ruleTable = optionsPane.getRuleTable();
            // table
            ruleTableModel = new RuleTableModel();
            //ruleTableSorter = new TableRowSorter<>(ruleTableModel);
            ruleTable.setModel(ruleTableModel);
            // ruleTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            // ruleTable.getTableHeader().setReorderingAllowed(true);
            ruleTable.setAutoCreateRowSorter(true);
            //ruleTable.setRowSorter(ruleTableSorter);
            for (int i = 0; i < ruleTableModel.getColumnCount(); i++) {
                TableColumn column = ruleTable.getColumnModel().getColumn(i);
                column.setMinWidth(20);
                column.setPreferredWidth(ruleTableModel.getPreferredWidth(i));
                int max = ruleTableModel.getMaxWidth(i);
                if (max != -1) {
                    column.setMaxWidth(max);
                }
            }
            callbacks.customizeUiComponent(ruleTable);
            // options tab wrapper
            optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            optionsTab.setFocusable(false);
            //
            JSplitPane optionsRuleTableSplitPane = optionsPane.getRuleTableSplitPane();
            optionsRuleTableSplitPane.setDividerSize(10);
            //optionsRuleTableSplitPane.setContinuousLayout(true);
            optionsRuleTableSplitPane.setUI(new GlyphSplitPaneUI(optionsPane.getBackground())); // each need separate instance
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(SecondOrderExtension.this);
            // context menu
            menu = new JMenu("Second order");
            addRequestMenuItem = new JMenuItem("Add request");
            addRequestMenuItem.addActionListener((ActionEvent e) -> {
                // add request
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages.length == 1) {
                    Rule rule = new Rule(messages[0]);
                    int row = rules.size();
                    rules.add(rule);
                    ruleTableModel.fireTableRowsInserted(row, row);
                }
            });
            menu.add(addRequestMenuItem);
            contextMenu.add(menu);
            callbacks.registerContextMenuFactory(SecondOrderExtension.this);
            // remove rule
            optionsPane.getRemoveRule().addActionListener((ActionEvent e) -> {
                int selected = ruleTable.getSelectedRow();
                if (selected == - 1) {
                    return;
                }
                int index = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
                rules.remove(index);
                int row = rules.size();
                ruleTableModel.fireTableRowsDeleted(row, row);
            });
            // clear rules
            optionsPane.getClearRules().addActionListener((ActionEvent e) -> {
                if (rules.isEmpty()) {
                    return;
                }
                rules.clear();
                int row = rules.size();
                ruleTableModel.fireTableRowsDeleted(row, row);
            });
            // get burp frame and tabbed pane handler
            //burpFrame = (JFrame) SwingUtilities.getWindowAncestor(optionsTab);
            //
            //int row = rules.size();
            //rules.add(new Rule());
            //rules.add(new Rule());
            //rules.add(new Rule());
            //ruleTableModel.fireTableRowsInserted(row, row);
            //
            callbacks.printOutput("Loaded.");
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
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        menu.setEnabled(messages != null);
        addRequestMenuItem.setEnabled(messages != null && messages.length == 1);
        this.invocation = invocation;
        return contextMenu;
    }

    //
    // misc
    //
    class Rule {

        private final IHttpRequestResponse requestResponse;
        private final String method;
        private final URL url;

        public Rule(IHttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse);
            method = requestInfo.getMethod();
            url = requestInfo.getUrl();
        }

        public IHttpRequestResponse getRequestResponse() {
            return requestResponse;
        }

        public String getMethod() {
            return method;
        }

        public URL getUrl() {
            return url;
        }
    }

    class RuleTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return rules.size();
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return true;
                case 3:
                    return true;
                default:
                    return false;
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            Rule rule = rules.get(rowIndex);
            // active
            if (columnIndex == 0) {
                if (active == rule) {
                    active = null;
                } else {
                    active = rule;
                }
                for (int i = 0; i < rules.size(); i++) {
                    fireTableCellUpdated(i, columnIndex);
                }
                JLabel state = optionsPane.getState();
                state.setText(active != null ? "Active" : "<html><i style='color:#e58900'>Inactive</i></html>");
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
            Rule rule = rules.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return rule.equals(active);
                case 1:
                    return rule.getMethod();
                case 2:
                    return rule.getUrl();
                case 3:
                    return rule.getRequestResponse().getComment();
                default:
                    return "";
            }
        }

        public int getPreferredWidth(int column) {
            switch (column) {
                case 0:
                    return 60;
                case 1:
                    return 60;
                case 2:
                    return 200;
                case 3:
                    return 120;
                default:
                    return 80;
            }
        }

        public int getMaxWidth(int column) {
            switch (column) {
                case 0:
                    return 60;
                case 1:
                    return 60;
                case 2:
                    return -1;
                case 3:
                    return 120;
                default:
                    return -1;
            }
        }
    }
}
