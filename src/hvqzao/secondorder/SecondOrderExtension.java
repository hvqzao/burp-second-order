// Token Second Order Extension, (c) 2016-2017 Marcin Woloszyn (@hvqzao), Released under MIT license
package hvqzao.secondorder;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.ITab;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Image;
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class SecondOrderExtension implements IBurpExtender, ITab {

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private JScrollPane optionsTab;
    private static boolean burpFree;
    private static ImageIcon iconHelp;
    private static ImageIcon iconDefaults;
    private static Dimension iconDimension;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        SecondOrderExtension.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        // set extension name
        callbacks.setExtensionName("Second Order");
        // detect burp flavor
        burpFree = String.valueOf(callbacks.getBurpVersion()[0]).equals("Burp Suite Free Edition");
        // draw UI
        SwingUtilities.invokeLater(() -> {
            // images
            iconHelp = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/secondorder/resources/panel_help.png")).getImage().getScaledInstance(13, 13, Image.SCALE_SMOOTH));
            iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource("/hvqzao/secondorder/resources/panel_defaults.png")).getImage().getScaledInstance(13, 13, Image.SCALE_SMOOTH));
            iconDimension = new Dimension(24, 24);
            // extension tab
            SecondOrderOptions optionsPane = new SecondOrderOptions();
            // options pane wrapper
            optionsTab = new JScrollPane(optionsPane, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            callbacks.customizeUiComponent(optionsTab);
            optionsTab.setFocusable(false);
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(SecondOrderExtension.this);
            optionsPane.start();
        });
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static ImageIcon getIconHelp() {
        return iconHelp;
    }

    public static ImageIcon getIconDefaults() {
        return iconDefaults;
    }

    public static Dimension getIconDimension() {
        return iconDimension;
    }

    public static boolean isBurpFree() {
        return burpFree;
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

}
