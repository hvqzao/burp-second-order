package hvqzao.secondorder;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

public class SecondOrderOptions extends JPanel implements IContextMenuFactory, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    //private JFrame burpFrame;
    private final ArrayList<Rule> rules = new ArrayList<>();
    private RuleTableModel ruleTableModel;
    private TableRowSorter<RuleTableModel> ruleTableSorter;
    private final List<JMenuItem> contextMenu = new ArrayList<>();
    private IContextMenuInvocation invocation;
    private JMenu menu;
    private JMenuItem addRequestMenuItem;
    private Rule active;

    public SecondOrderOptions() {
        initComponents();
        initialize();
    }

    private void initialize() {
        callbacks = BurpExtender.getCallbacks();

        callbacks.customizeUiComponent(this);

        callbacks.customizeUiComponent(optionsHelp);
        callbacks.customizeUiComponent(optionsDefaults);
        callbacks.customizeUiComponent(ruleTable);
        callbacks.customizeUiComponent(removeRule);
        callbacks.customizeUiComponent(clearRules);
        callbacks.customizeUiComponent(ruleTableSplitPane);
        callbacks.customizeUiComponent(scanner);
        callbacks.customizeUiComponent(intruder);
        callbacks.customizeUiComponent(repeater);
        callbacks.customizeUiComponent(extender);

        scanner.setEnabled(BurpExtender.isBurpFree() == false);
        //
        optionsHelp.setIcon(BurpExtender.getIconHelp());
        optionsHelp.setEnabled(false);
        //
        optionsDefaults.setIcon(BurpExtender.getIconDefaults());
        optionsDefaults.setEnabled(false);
        // table
        ruleTableModel = new RuleTableModel();
        ruleTableSorter = new TableRowSorter<>(ruleTableModel);
        ruleTable.setModel(ruleTableModel);
        // ruleTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        // ruleTable.getTableHeader().setReorderingAllowed(true);
        ruleTable.setAutoCreateRowSorter(true);
        ruleTable.setRowSorter(ruleTableSorter);
        for (int i = 0; i < ruleTableModel.getColumnCount(); i++) {
            TableColumn column = ruleTable.getColumnModel().getColumn(i);
            column.setMinWidth(20);
            column.setPreferredWidth(ruleTableModel.getPreferredWidth(i));
            int max = ruleTableModel.getMaxWidth(i);
            if (max != -1) {
                column.setMaxWidth(max);
            }
        }
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
        // remove rule
        removeRule.addActionListener((ActionEvent e) -> {
            int selected = ruleTable.getSelectedRow();
            if (selected == - 1) {
                return;
            }
            int index = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
            if (rules.get(index) == active) {
                active = null;
                updateState();
            }
            rules.remove(index);
            int row = rules.size();
            ruleTableModel.fireTableRowsDeleted(row, row);
        });
        // clear rules
        clearRules.addActionListener((ActionEvent e) -> {
            if (rules.isEmpty()) {
                return;
            }
            active = null;
            updateState();
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
        //
    }

    public void start() {
        callbacks.registerContextMenuFactory(this);
        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
        // split pane UI
        ruleTableSplitPane.setDividerSize(10);
        //optionsRuleTableSplitPane.setContinuousLayout(true);
        ruleTableSplitPane.setUI(new GlyphSplitPaneUI(getBackground())); // each need separate instance
        //callbacks.printOutput("Loaded.");
    }

    void updateState() {
        state.setText(active != null ? "<html><b>&nbsp;Active</b></html>" : "<html><i style='color:#e58900'>Inactive</i></html>");
    }

    private class Rule {

        private final IHttpRequestResponse requestResponse;
        private final String method;
        private final URL url;

        public Rule(IHttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            IRequestInfo requestInfo = BurpExtender.getHelpers().analyzeRequest(requestResponse);
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

    private class RuleTableModel extends AbstractTableModel {

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
                updateState();
            }
            // comment
            if (columnIndex == 3) {
                rule.getRequestResponse().setComment((String) aValue);
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
                    return rule.getUrl().toString();
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

    //
    // implement IHttpListener
    //
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // lets keep local reference to avoid race condition
        Rule rule = active;
        // is rule set?
        if (rule != null && messageIsRequest == false) {
            // we are interested in responses only
            if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
                // quick return on TOOL_PROXY & TOOL_SPIDER
                return;
            }
            if ((toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER && scanner.isSelected())
                    || (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER && intruder.isSelected())
                    || (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER && repeater.isSelected())
                    || (toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER && extender.isSelected())) {
                IHttpRequestResponse baseRequestResponse = rule.getRequestResponse();
                byte[] request = baseRequestResponse.getRequest();
                if (toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER && extender.isSelected() && Arrays.equals(messageInfo.getRequest(), request)) {
                    // avoid infinite loop of requests
                    return;
                }
                // issue second order request and replace response in SCANNER / INTRUDER / REPEATER / EXTENDER request
                IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);
                messageInfo.setResponse(requestResponse.getResponse());
            }
        }
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

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        optionsHelp = new javax.swing.JButton();
        optionsDefaults = new javax.swing.JButton();
        optionsRewriteTitle = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        removeRule = new javax.swing.JButton();
        clearRules = new javax.swing.JButton();
        ruleTableSplitPane = new javax.swing.JSplitPane();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        ruleTable = new javax.swing.JTable();
        jLabel2 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        scanner = new javax.swing.JCheckBox();
        intruder = new javax.swing.JCheckBox();
        extender = new javax.swing.JCheckBox();
        state = new javax.swing.JLabel();
        repeater = new javax.swing.JCheckBox();

        setBorder(javax.swing.BorderFactory.createEmptyBorder(5, 5, 5, 5));

        optionsHelp.setMargin(new java.awt.Insets(0, 0, 0, 0));
        optionsHelp.setMaximumSize(new java.awt.Dimension(24, 24));
        optionsHelp.setMinimumSize(new java.awt.Dimension(24, 24));
        optionsHelp.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsDefaults.setMargin(new java.awt.Insets(0, 0, 0, 0));
        optionsDefaults.setMaximumSize(new java.awt.Dimension(24, 24));
        optionsDefaults.setMinimumSize(new java.awt.Dimension(24, 24));
        optionsDefaults.setPreferredSize(new java.awt.Dimension(24, 24));

        optionsRewriteTitle.setText("<html><b style='color:#e58900;font-size:10px'>Second Order</b></html>");
        optionsRewriteTitle.setToolTipText("");

        jLabel1.setText("<html>The purpose of this extension is to allow semi-automated detection of second order issues.</html>");

        removeRule.setText("Remove");

        clearRules.setText("Clear");

        ruleTableSplitPane.setDividerLocation(550);

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 0, Short.MAX_VALUE)
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 152, Short.MAX_VALUE)
        );

        ruleTableSplitPane.setRightComponent(jPanel3);

        ruleTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        jScrollPane1.setViewportView(ruleTable);

        ruleTableSplitPane.setLeftComponent(jScrollPane1);

        jLabel2.setText("Extension state:");

        jLabel4.setText("Tools in scope:");

        scanner.setSelected(true);
        scanner.setText("Scanner");

        intruder.setSelected(true);
        intruder.setText("Intruder");

        extender.setText("Extender (use with caution)");

        state.setText("<html><i style='color:#e58900'>Inactive</i></html>");

        repeater.setSelected(true);
        repeater.setText("Repeater");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(optionsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(optionsRewriteTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(optionsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(clearRules, javax.swing.GroupLayout.PREFERRED_SIZE, 74, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(removeRule, javax.swing.GroupLayout.PREFERRED_SIZE, 74, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(ruleTableSplitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 621, Short.MAX_VALUE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addGap(18, 18, 18)
                        .addComponent(state, javax.swing.GroupLayout.PREFERRED_SIZE, 59, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel4)
                        .addGap(18, 18, 18)
                        .addComponent(scanner)
                        .addGap(6, 6, 6)
                        .addComponent(intruder)
                        .addGap(6, 6, 6)
                        .addComponent(repeater)
                        .addGap(6, 6, 6)
                        .addComponent(extender)
                        .addContainerGap())))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(optionsHelp, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(optionsDefaults, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(optionsRewriteTitle, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(16, 16, 16)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(removeRule)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(clearRules))
                            .addComponent(ruleTableSplitPane, javax.swing.GroupLayout.DEFAULT_SIZE, 154, Short.MAX_VALUE))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel4)
                        .addComponent(scanner)
                        .addComponent(intruder)
                        .addComponent(extender)
                        .addComponent(state, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(repeater)))
                .addGap(0, 0, 0))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton clearRules;
    private javax.swing.JCheckBox extender;
    private javax.swing.JCheckBox intruder;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton optionsDefaults;
    private javax.swing.JButton optionsHelp;
    private javax.swing.JLabel optionsRewriteTitle;
    private javax.swing.JButton removeRule;
    private javax.swing.JCheckBox repeater;
    private javax.swing.JTable ruleTable;
    private javax.swing.JSplitPane ruleTableSplitPane;
    private javax.swing.JCheckBox scanner;
    private javax.swing.JLabel state;
    // End of variables declaration//GEN-END:variables
}
