package burp;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.Document;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.compressors.CompressorException;
import org.apache.commons.compress.compressors.CompressorOutputStream;
import org.apache.commons.compress.compressors.CompressorStreamFactory;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.jcajce.provider.digest.Skein;
import org.bouncycastle.util.encoders.Hex;
import org.unbescape.css.CssEscape;
import org.unbescape.css.CssStringEscapeLevel;
import org.unbescape.css.CssStringEscapeType;
import org.unbescape.html.HtmlEscape;
import org.unbescape.html.HtmlEscapeLevel;
import org.unbescape.html.HtmlEscapeType;
import org.unbescape.javascript.JavaScriptEscape;
import org.unbescape.javascript.JavaScriptEscapeLevel;
import org.unbescape.javascript.JavaScriptEscapeType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.lang.reflect.Method;
import java.util.stream.IntStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static java.awt.GridBagConstraints.*;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IExtensionStateListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JTabbedPaneClosable inputTabs;
	private int tabCounter = 1;
	private PrintWriter stderr;
	private PrintWriter stdout;
	private Hackvertor hv;
	private Hackvertor hvInRequest;
	private boolean tagsInProxy = false;
    private boolean tagsInIntruder = true;
    private boolean tagsInRepeater = true;
    private boolean tagsInScanner = true;
    private JMenuBar burpMenuBar;
    private JMenu hvMenuBar;
    private Ngrams ngrams;

	private GridBagConstraints createConstraints(int x, int y, int gridWidth) {
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0;
        c.weighty = 0;
        c.gridx = x;
        c.gridy = y;
        c.ipadx = 0;
        c.ipady = 0;
        c.gridwidth = gridWidth;            
		return c;
	}
	private ImageIcon createImageIcon(String path, String description) {
		java.net.URL imgURL = getClass().getResource(path);
        if (imgURL != null) {
			return new ImageIcon(imgURL, description);
		} else {
			stderr.println("Couldn't find file: " + path);
			return null;
		}
	}
	private boolean hasMethodAnd1Arg(Object obj, String methodStr) {
		boolean hasMethod = false;
		Method[] methods = obj.getClass().getMethods();
		for (Method m : methods) {
		  if (m.getName().equals(methodStr) && m.getParameterTypes().length == 1) {
		    hasMethod = true;
		    break;
		  }
		}
		
		return hasMethod;
	}
	private JPanel generateBlankPanel() {
        JPanel blankPanel = new JPanel();
        blankPanel.setMaximumSize(new Dimension(0,0));
        blankPanel.setVisible(false);
        return blankPanel;
    }
    private Hackvertor generateHackvertor() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setAutoscrolls(true);
        hv = new Hackvertor();
        hv.init();
        hv.buildTabs(tabs);
        JPanel topBar = new JPanel(new GridBagLayout());
        topBar.setPreferredSize(new Dimension(-1, 100));
        topBar.setMinimumSize(new Dimension(-1, 100));
        JLabel logoLabel = new JLabel(createImageIcon("/images/logo.gif","logo"));
        final JTextArea hexView = new JTextArea();
        hexView.setRows(0);
        hexView.setOpaque(true);
        hexView.setEditable(false);
        hexView.setLineWrap(true);
        hexView.setBackground(Color.decode("#FFF5BF"));
        hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        hexView.setVisible(false);
        final JScrollPane hexScroll = new JScrollPane(hexView);
        hexScroll.setPreferredSize(new Dimension(-1,100));
        hexScroll.setMinimumSize(new Dimension(-1,100));
        JPanel buttonsPanel = new JPanel(new GridLayout(1, 0, 10, 0));
        JPanel panel = new JPanel(new GridBagLayout());
        hv.setPanel(panel);
        final JTextArea inputArea = new JTextArea();
        hv.setInputArea(inputArea);
        inputArea.setLineWrap(true);
        inputArea.setRows(0);
        final UndoManager undo = new UndoManager();
        Document doc = inputArea.getDocument();

        doc.addUndoableEditListener(new UndoableEditListener() {
            public void undoableEditHappened(UndoableEditEvent evt) {
                undo.addEdit(evt.getEdit());
            }
        });
        inputArea.getActionMap().put("Undo",
                new AbstractAction("Undo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canUndo()) {
                                undo.undo();
                            }
                        } catch (CannotUndoException e) {
                        }
                    }
                });
        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Z"), "Undo");
        inputArea.getActionMap().put("Redo",
                new AbstractAction("Redo") {
                    public void actionPerformed(ActionEvent evt) {
                        try {
                            if (undo.canRedo()) {
                                undo.redo();
                            }
                        } catch (CannotRedoException e) {
                        }
                    }
                });

        inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Y"), "Redo");
        final JScrollPane inputScroll = new JScrollPane(inputArea);
        final JLabel inputLabel = new JLabel("Input:");
        final JLabel inputLenLabel = new JLabel("0");
        final JLabel inputRealLenLabel = new JLabel("0");
        inputRealLenLabel.setOpaque(true);
        inputRealLenLabel.setForeground(Color.decode("#ffffff"));
        inputRealLenLabel.setBackground(Color.decode("#ff0027"));
        inputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        inputLenLabel.setOpaque(true);
        inputLenLabel.setBackground(Color.decode("#FFF5BF"));
        inputLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        final JTextArea outputArea = new JTextArea();
        hv.setOutputArea(outputArea);
        DocumentListener documentListener = new DocumentListener() {
            public void changedUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hv.convert(inputArea.getText()));
            }
            public void insertUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hv.convert(inputArea.getText()));
            }
            public void removeUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
                outputArea.setText(hv.convert(inputArea.getText()));
            }
            private void updateLen(DocumentEvent documentEvent) {
                int len = inputArea.getText().length();
                int realLen = hv.calculateRealLen(inputArea.getText());
                inputLenLabel.setText(""+len);
                inputRealLenLabel.setText(""+realLen);
            }
        };
        inputArea.getDocument().addDocumentListener(documentListener);
        inputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    if (e.getModifiers() > 0) {
                        inputArea.transferFocusBackward();
                    } else {
                        inputArea.transferFocus();
                    }
                    e.consume();
                }
            }
        });
        inputArea.addCaretListener(new CaretListener()
        {
            public void caretUpdate(CaretEvent e) {
                String selectedText = inputArea.getSelectedText();
                if(selectedText != null) {
                    hexView.setVisible(true);
                    String output = hv.ascii2hex(selectedText, " ");
                    hexView.setText(output);
                } else {
                    hexView.setVisible(false);
                    hexView.setText("");
                }
            }
        });
        outputArea.setRows(0);
        outputArea.setLineWrap(true);
        outputArea.addCaretListener(new CaretListener()
        {
            public void caretUpdate(CaretEvent e) {
                String selectedText = outputArea.getSelectedText();
                if(selectedText != null) {
                    hexView.setVisible(true);
                    String output = hv.ascii2hex(selectedText, " ");
                    hexView.setText(output);
                } else {
                    hexView.setVisible(false);
                    hexView.setText("");
                }
            }
        });
        final JScrollPane outputScroll = new JScrollPane(outputArea);
        final JLabel outputLabel = new JLabel("Output:");
        final JLabel outputLenLabel = new JLabel("0");
        final JLabel outputRealLenLabel = new JLabel("0");
        outputRealLenLabel.setOpaque(true);
        outputRealLenLabel.setForeground(Color.decode("#ffffff"));
        outputRealLenLabel.setBackground(Color.decode("#ff0027"));
        outputRealLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#CCCCCC"), 1));
        outputLenLabel.setOpaque(true);
        outputLenLabel.setBackground(Color.decode("#FFF5BF"));
        outputLenLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        DocumentListener documentListener2 = new DocumentListener() {
            public void changedUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }
            public void insertUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }
            public void removeUpdate(DocumentEvent documentEvent) {
                updateLen(documentEvent);
            }
            private void updateLen(DocumentEvent documentEvent) {
                int len = outputArea.getText().length();
                int realLen = hv.calculateRealLen(outputArea.getText());
                outputLenLabel.setText(""+len);
                outputRealLenLabel.setText(""+realLen);
            }
        };
        outputArea.getDocument().addDocumentListener(documentListener2);
        outputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_TAB) {
                    if (e.getModifiers() > 0) {
                        outputArea.transferFocusBackward();
                    } else {
                        outputArea.transferFocus();
                    }
                    e.consume();
                }
            }
        });
        final JButton swapButton = new JButton("Swap");
        swapButton.setBackground(Color.black);
        swapButton.setForeground(Color.white);
        swapButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText(outputArea.getText());
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });
        final JButton selectInputButton = new JButton("Select input");
        selectInputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.requestFocus();
                inputArea.selectAll();
            }
        });
        selectInputButton.setForeground(Color.white);
        selectInputButton.setBackground(Color.black);
        final JButton selectOutputButton = new JButton("Select output");
        selectOutputButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.requestFocus();
                outputArea.selectAll();
            }
        });
        selectOutputButton.setForeground(Color.white);
        selectOutputButton.setBackground(Color.black);
        final JButton clearTagsButton = new JButton("Clear tags");
        clearTagsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                hv.clearTags();
            }
        });
        clearTagsButton.setForeground(Color.white);
        clearTagsButton.setBackground(Color.black);
        final JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                inputArea.setText("");
                outputArea.setText("");
                inputArea.requestFocus();
            }
        });
        clearButton.setForeground(Color.white);
        clearButton.setBackground(Color.black);
        final JButton pasteInsideButton = new JButton("Paste inside tags");
        pasteInsideButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.setText("");
                String input = inputArea.getText();
                try {
                    input = input.replaceAll("((?:<@?\\w+_\\d+(?:[(](?:,?"+hv.argumentsRegex+")*[)])?>)+)[\\s\\S]*?(?:<@/)","$1"+Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor).toString()+"<@/");
                    hv.setInput(input);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
        pasteInsideButton.setForeground(Color.white);
        pasteInsideButton.setBackground(Color.black);
        final JButton convertButton = new JButton("Convert");
        convertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                outputArea.setText(hv.convert(inputArea.getText()));
            }
        });
        convertButton.setBackground(Color.decode("#005a70"));
        convertButton.setForeground(Color.white);
        buttonsPanel.add(clearButton);
        buttonsPanel.add(clearTagsButton);
        buttonsPanel.add(swapButton);
        buttonsPanel.add(selectInputButton);
        buttonsPanel.add(selectOutputButton);
        buttonsPanel.add(pasteInsideButton);
        buttonsPanel.add(convertButton);
        GridBagConstraints c = createConstraints(1,0,1);
        c.anchor = FIRST_LINE_END;
        c.ipadx = 20;
        c.ipady = 20;
        topBar.add(logoLabel,c);
        c = createConstraints(0, 0, 1);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        c.weighty = 1;
        topBar.add(tabs, c);
        c = createConstraints(0,0,2);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        panel.add(topBar,c);
        JPanel inputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = createConstraints(0,0,1);
        c.insets = new Insets(5,5,5,5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLabel,c);
        c = createConstraints(1,1,1);
        c.insets = new Insets(5,5,5,5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLenLabel,c);
        c = createConstraints(2,1,1);
        c.insets = new Insets(5,5,5,5);
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputRealLenLabel,c);
        panel.add(inputLabelsPanel,createConstraints(0,2,1));
        c = createConstraints(0,3,1);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 0.5;
        c.weighty = 1.0;
        panel.add(inputScroll,c);
        JPanel outputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = createConstraints(0,1,1);
        c.insets = new Insets(5,5,5,5);
        outputLabelsPanel.add(outputLabel,c);
        c = createConstraints(1,1,1);
        c.insets = new Insets(5,5,5,5);
        outputLabelsPanel.add(outputLenLabel,c);
        c = createConstraints(2,1,1);
        c.insets = new Insets(5,5,5,5);
        outputLabelsPanel.add(outputRealLenLabel,c);
        panel.add(outputLabelsPanel,createConstraints(1,2,1));
        c = createConstraints(1,3,1);
        c.anchor = FIRST_LINE_START;
        c.fill = BOTH;
        c.weightx = 0.5;
        c.weighty = 1.0;
        panel.add(outputScroll,c);
        c = createConstraints(0,4,2);
        c.anchor = GridBagConstraints.SOUTH;
        c.fill = BOTH;
        c.weightx = 1.0;
        panel.add(buttonsPanel,c);
        c = createConstraints(0,5,2);
        c.insets = new Insets(5,5,5,5);
        c.anchor = LAST_LINE_START;
        c.fill = BOTH;
        c.weightx = 1.0;
        panel.add(hexScroll,c);
        callbacks.customizeUiComponent(inputArea);
        callbacks.customizeUiComponent(outputArea);
        callbacks.customizeUiComponent(panel);
        callbacks.customizeUiComponent(inputTabs);
        return hv;
    }

	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		helpers = callbacks.getHelpers();
		stderr = new PrintWriter(callbacks.getStderr(), true);
		stdout = new PrintWriter(callbacks.getStdout(), true);
		try {
            ngrams = new Ngrams("/quadgrams.txt");
        } catch (IOException e) {
            stderr.println(e.getMessage());
        }
        this.callbacks = callbacks;
		callbacks.setExtensionName("Hackvertor");
		callbacks.registerContextMenuFactory(this);
		callbacks.registerHttpListener(this);
		callbacks.registerExtensionStateListener(this);
		Security.addProvider(new BouncyCastleProvider());
        SwingUtilities.invokeLater(new Runnable()
	        {
	            public void run()
	            {	   
	            	stdout.println("Hackvertor v0.6.7");
	            	inputTabs = new JTabbedPaneClosable();
	            	final Hackvertor mainHV = generateHackvertor();
	            	hv = mainHV;
	            	hv.getPanel().addComponentListener(new ComponentAdapter() {
                        @Override
                        public void componentShown(ComponentEvent e) {
                            hv = mainHV;
                        }
                    });
                    inputTabs.addTab("1", hv.getPanel());
                    inputTabs.addTab("...", generateBlankPanel());
	            	inputTabs.addChangeListener(new ChangeListener() {
                        public void stateChanged(ChangeEvent e) {
                            if (e.getSource() instanceof JTabbedPane) {
                                JTabbedPaneClosable pane = (JTabbedPaneClosable) e.getSource();
                                if(pane.getSelectedIndex() == -1) {
                                    return;
                                }
                                if(pane.clickedDelete) {
                                    pane.clickedDelete = false;
                                    if(pane.getTabCount() > 1) {
                                        if(pane.getSelectedIndex() == pane.getTabCount()-1) {
                                            pane.setSelectedIndex(pane.getTabCount()-2);
                                        }
                                        return;
                                    }
                                }
                                 if(pane.getTitleAt(pane.getSelectedIndex()).equals("...")) {
                                    tabCounter++;
                                    final Hackvertor hvTab = generateHackvertor();
                                    JPanel panel = hvTab.getPanel();
                                    panel.addComponentListener(new ComponentAdapter() {
                                        @Override
                                        public void componentShown(ComponentEvent e) {
                                            hv = hvTab;
                                        }
                                    });
                                    pane.remove(pane.getSelectedIndex());
                                    pane.addTab(tabCounter+"", panel);
                                    pane.addTab("...", generateBlankPanel());
                                    pane.setSelectedIndex(pane.getTabCount()-2);
                                }
                            }
                        }
                    });
	                callbacks.addSuiteTab(BurpExtender.this);
                    burpMenuBar = getBurpFrame().getJMenuBar();
                    hvMenuBar = new JMenu("Hackvertor");
                    final JCheckBoxMenuItem tagsInProxyMenu = new JCheckBoxMenuItem(
                            "Allow tags in Proxy", tagsInProxy);
                    tagsInProxyMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if(tagsInProxyMenu.getState()){
                                tagsInProxy = true;
                            } else {
                                tagsInProxy = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInProxyMenu);
                    final JCheckBoxMenuItem tagsInIntruderMenu = new JCheckBoxMenuItem(
                            "Allow tags in Intruder", tagsInIntruder);
                    tagsInIntruderMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if(tagsInIntruderMenu.getState()){
                                tagsInIntruder = true;
                            } else {
                                tagsInIntruder = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInIntruderMenu);
                    final JCheckBoxMenuItem tagsInRepeaterMenu = new JCheckBoxMenuItem(
                            "Allow tags in Repeater", tagsInRepeater);
                    tagsInRepeaterMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if(tagsInRepeaterMenu.getState()){
                                tagsInRepeater = true;
                            } else {
                                tagsInRepeater = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInRepeaterMenu);
                    final JCheckBoxMenuItem tagsInScannerMenu = new JCheckBoxMenuItem(
                            "Allow tags in Scanner", tagsInScanner);
                    tagsInScannerMenu.addItemListener(new ItemListener() {
                        public void itemStateChanged(ItemEvent e) {
                            if(tagsInScannerMenu.getState()){
                                tagsInScanner = true;
                            } else {
                                tagsInScanner = false;
                            }
                        }
                    });
                    hvMenuBar.add(tagsInScannerMenu);
                    burpMenuBar.add(hvMenuBar);
	            }
	        });
		
	}

	public void extensionUnloaded() {
	    burpMenuBar.remove(hvMenuBar);
	    burpMenuBar.repaint();
        stdout.println("Hackvertor unloaded");
    }

    public byte[] fixContentLength(byte[] request) {
        IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
        if (countMatches(request, helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = analyzedRequest.getBodyOffset();
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        }
        else {
            return request;
        }
    }

    public int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ' ') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    public  byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write( Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(helpers.stringToBytes(value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        } catch (NullPointerException e) {
            throw new RuntimeException("Can't find the header");
        }
    }

    int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(!messageIsRequest) {
            return;
        }
        switch(toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                if(!tagsInProxy) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                if(!tagsInIntruder) {
                    return;
                }
                 break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                if(!tagsInRepeater) {
                    return;
                }
                break;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                if(!tagsInScanner) {
                    return;
                }
                break;
            default:
                return;
        }
        byte[] request = messageInfo.getRequest();
	    if(helpers.indexOf(request,helpers.stringToBytes("<@/"), true, 0, request.length) > -1 || helpers.indexOf(request,helpers.stringToBytes(" @/>"), true, 0, request.length) > -1) {
	        Hackvertor hv = new Hackvertor();
	        request = helpers.stringToBytes(hv.convert(helpers.bytesToString(request)));
            request = fixContentLength(request);
            messageInfo.setRequest(request);
        }
    }

    private static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

	public String getTabCaption() {
		return "Hackvertor";
	}
	
	private int getTabIndex(ITab your_itab) {
		JTabbedPane parent = (JTabbedPane) your_itab.getUiComponent().getParent();
		for(int i = 0; i < parent.getTabCount(); ++i) {
			if(your_itab.getTabCaption().equals(parent.getTitleAt(i))) {
				return i;
			}
		}
		return -1;
	}
    public String buildUrl(URL url) {
        int port = url.getPort();
        StringBuilder urlResult = new StringBuilder();
        urlResult.append(url.getProtocol());
        urlResult.append(":");
        if (url.getAuthority() != null && url.getAuthority().length() > 0) {
            urlResult.append("//");
            urlResult.append(url.getHost());
        }

        if ((url.getProtocol().equals("http") && port != 80) || (url.getProtocol().equals("https") && port != 443) && port != -1) {
            urlResult.append(':').append(port);
        }
        if (url.getPath() != null) {
            urlResult.append(url.getPath());
        }
        if(url.getQuery() != null) {
            urlResult.append("?");
            urlResult.append(url.getQuery());
        }
        if (url.getRef() != null) {
            urlResult.append("#");
            urlResult.append(url.getRef());
        }
        return urlResult.toString();
    }
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		int[] bounds = invocation.getSelectionBounds();
		
		switch (invocation.getInvocationContext()) {
			case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
			break;
			default:
				return null;
		}
        List<JMenuItem> menu = new ArrayList<JMenuItem>();
        JMenu submenu = new JMenu("Hackvertor");
        Action hackvertorAction = new HackvertorAction("Send to Hackvertor", invocation);
        JMenuItem sendToHackvertor = new JMenuItem(hackvertorAction); 
        submenu.add(sendToHackvertor);
        if(hvInRequest == null) {
            hvInRequest = new Hackvertor();
            hvInRequest.init();
        }
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            Hackvertor hv = new Hackvertor();
            URL url = helpers.analyzeRequest(invocation.getSelectedMessages()[0].getHttpService(), helpers.stringToBytes(hv.convert(helpers.bytesToString(invocation.getSelectedMessages()[0].getRequest())))).getUrl();
            StringSelection stringSelection = null;
            stringSelection = new StringSelection(buildUrl(url));
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        });
        submenu.add(copyUrl);

        String[] categories = hv.getCategories();
        for(int i=0;i<categories.length;i++) {
            JMenu categoryMenu = new JMenu(categories[i]);
            String category = categories[i];
            hvInRequest.createButtonsOrMenu(category, "menu", categoryMenu, invocation);
            submenu.add(categoryMenu);
        }
        menu.add(submenu);
        return menu;
    }
	class HackvertorAction extends AbstractAction {

        IContextMenuInvocation invocation;
        private static final long serialVersionUID = 1L;
        
        HackvertorAction(String text, IContextMenuInvocation invocation) {
            super(text);
            this.invocation = invocation;	          
        }

        public void actionPerformed(ActionEvent e) {
        	byte[] message = null;
        	switch (invocation.getInvocationContext()) {
        		case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
        		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
        		case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
        			message = invocation.getSelectedMessages()[0].getRequest();		        			
        		break;
        		case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:     		
        			message = invocation.getSelectedMessages()[0].getResponse();	        		
        		break;	    
        	}  	
        	int[] bounds = invocation.getSelectionBounds(); 	        
        	if(bounds[0] != bounds[1] && message != null) {
        		hv.setInput((new String(message).substring(bounds[0], bounds[1])).trim());
        		JTabbedPane tp = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
				int tIndex = getTabIndex(BurpExtender.this);
				if(tIndex > -1) {
					tp.setSelectedIndex(tIndex);
				}
        	}
        }
        
    }
	public void alert(String msg) {
		JOptionPane.showMessageDialog(null, msg);
	}
	public Component getUiComponent() {
        return inputTabs;
    }
	class HackvertorPayloadProcessor implements IIntruderPayloadProcessor {
		String name;
		String tag;
		public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
			String input = helpers.bytesToString(helpers.urlDecode(currentPayload));
			byte[] output = helpers.stringToBytes(helpers.urlEncode(hv.callTag(this.tag,input,new ArrayList<String>())));
			return output;
		}
		public String getProcessorName() {
			return this.name;
		}
		HackvertorPayloadProcessor(String name, String tag) {
			this.name = name;
			this.tag = tag;
		}
	}
	class Tag {
		String category;
		String name;
		boolean hasInput = true;
		String tooltip;
		TagArgument argument1 = null;
		TagArgument argument2 = null;
		TagArgument argument3 = null;
		Tag(String tagCategory, String tagName, boolean hasInput, String tooltip) {
			this.category = tagCategory;
			this.name = tagName;
			this.hasInput = hasInput;
			this.tooltip = tooltip;
			if(hasMethodAnd1Arg(hv,tagName)) {
				callbacks.registerIntruderPayloadProcessor(new HackvertorPayloadProcessor("Hackvertor_"+hv.capitalise(tagName),tagName));
			}
		}
	}
	class TagArgument {
		String type;
		String value;
		TagArgument(String type, String value) {
			this.type = type;
			this.value = value;
		}
	}
	class Hackvertor {	
		private int tagCounter = 0;
		String argumentsRegex = "(?:0x[a-fA-F0-9]+|\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")";
		private ArrayList<Tag> tags = new ArrayList<Tag>();
		private JTextArea inputArea;
        private JTextArea outputArea;
        private JPanel panel;
        private String[] categories = {
                "Charsets","Compression","Encrypt","Encode","Decode","Convert","String","Hash","Math","XSS"
        };
        void setInputArea(JTextArea inputArea) {
            this.inputArea = inputArea;
        }
        void setOutputArea(JTextArea outputArea) {
            this.outputArea = outputArea;
        }
        void setPanel(JPanel panel) {
            this.panel = panel;
        }
        JPanel getPanel() {
            return this.panel;
        }
		void buildTabs(JTabbedPane tabs) {
            for(int i=0;i<categories.length;i++) {
                tabs.addTab(categories[i], createButtonsOrMenu(categories[i],"button", null, null));
            }
		}
		String[] getCategories() {
            return categories;
        }
        public ArrayList<Tag> getTags(){
            return tags;
        }
		void init() {
			Tag tag;
            tags.add(new Tag("Charsets","utf16",true, "utf16(String input)"));
            tags.add(new Tag("Charsets","utf16be",true,"utf16be(String input)"));
            tags.add(new Tag("Charsets","utf16le",true, "utf16le(String input)"));
            tags.add(new Tag("Charsets","utf32",true,"utf32(String input)"));
            tags.add(new Tag("Charsets","shift_jis",true,"shift_jis(String input)"));
            tags.add(new Tag("Charsets","gb2312",true,"gb2312(String input)"));
            tags.add(new Tag("Charsets","euc_kr",true,"euc_kr(String input)"));
            tags.add(new Tag("Charsets","euc_jp",true, "euc_jp(String input)"));
            tags.add(new Tag("Charsets","gbk",true,"gbk(String input)"));
            tags.add(new Tag("Charsets","big5",true,"big5(String input)"));
            tag = new Tag("Charsets","charset_convert",true,"charset_convert(String input, String from, String to)");
            tag.argument1 = new TagArgument("string","from");
            tag.argument2 = new TagArgument("string","to");
            tags.add(tag);
            tags.add(new Tag("Compression","gzip_compress",true,"gzip_compress(String str)"));
            tags.add(new Tag("Compression","gzip_decompress",true,"gzip_decompress(String str)"));
            tags.add(new Tag("Compression","bzip2_compress",true,"bzip2_compress(String str)"));
            tags.add(new Tag("Compression","bzip2_decompress",true,"bzip2_decompress(String str)"));
            tags.add(new Tag("Compression","deflate_compress",true,"deflate_compress(String str)"));
            tags.add(new Tag("Compression","deflate_decompress",true,"deflate_decompress(String str)"));
            tag = new Tag("Encrypt","rotN",true,"rotN(String str, int n)");
            tag.argument1 = new TagArgument("int","13");
            tags.add(tag);
            tag = new Tag("Encrypt","xor",true,"xor(String message, String key)");
            tag.argument1 = new TagArgument("string","key");
            tags.add(tag);
            tag = new Tag("Encrypt","xor_decrypt",true,"xor_decrypt(String ciphertext, int keyLength)");
            tag.argument1 = new TagArgument("int","10");
            tags.add(tag);
            tags.add(new Tag("Encrypt","xor_getkey",true,"xor_getkey(String ciphertext)"));
            tag = new Tag("Encrypt","affine_encrypt",true,"affine_encrypt(String message, int key1, int key2)");
            tag.argument1 = new TagArgument("int","5");
            tag.argument2 = new TagArgument("int","9");
            tags.add(tag);
            tag = new Tag("Encrypt","affine_decrypt",true,"affine_decrypt(String ciphertext, int key1, int key2)");
            tag.argument1 = new TagArgument("int","5");
            tag.argument2 = new TagArgument("int","9");
            tags.add(tag);
            tags.add(new Tag("Encrypt","atbash_encrypt",true,"atbash_encrypt(String message)"));
            tags.add(new Tag("Encrypt","atbash_decrypt",true,"atbash_decrypt(String ciphertext)"));
            tags.add(new Tag("Encrypt","rotN_bruteforce",true,"rotN_bruteforce(String str)"));
            tag = new Tag("Encrypt","rail_fence_encrypt",true,"rail_fence_encrypt(String message, int key)");
            tag.argument1 = new TagArgument("int","4");
            tags.add(tag);
            tag = new Tag("Encrypt","rail_fence_decrypt",true,"rail_fence_decrypt(String encoded, int key)");
            tag.argument1 = new TagArgument("int","4");
            tags.add(tag);
            tag = new Tag("Encrypt","substitution_encrypt",true,"substitution_encrypt(String message, String key)");
            tag.argument1 = new TagArgument("string","phqgiumeaylnofdxjkrcvstzwb");
            tags.add(tag);
            tag = new Tag("Encrypt","substitution_decrypt",true,"substitution_decrypt(String ciphertext, String key)");
            tag.argument1 = new TagArgument("string","phqgiumeaylnofdxjkrcvstzwb");
            tags.add(tag);
            tags.add(new Tag("Encrypt","is_like_english",true,"is_like_english(String str)"));
            tags.add(new Tag("Encrypt","index_of_coincidence",true,"index_of_coincidence(String str)"));
            tags.add(new Tag("Encrypt","guess_key_length",true,"guess_key_length(String ciphertext)"));
            tags.add(new Tag("Encode","base32",true,"base32_encode(String str)"));
			tags.add(new Tag("Encode","base64",true,"base64Encode(String str)"));
            tags.add(new Tag("Encode","base64url",true,"base64urlEncode(String str)"));
			tags.add(new Tag("Encode","html_entities",true,"html_entities(String str)"));
			tags.add(new Tag("Encode","html5_entities",true,"html5_entities(String str)"));
            tag = new Tag("Encode","hex",true,"hex(String str, String separator)");
            tag.argument1 = new TagArgument("string"," ");
            tags.add(tag);
			tags.add(new Tag("Encode","hex_entities",true,"hex_entities(String str)"));
			tags.add(new Tag("Encode","hex_escapes",true,"hex_escapes(String str)"));
			tags.add(new Tag("Encode","octal_escapes",true,"octal_escapes(String str)"));
			tags.add(new Tag("Encode","dec_entities",true,"dec_entities(String str)"));
			tags.add(new Tag("Encode","unicode_escapes",true,"unicode_escapes(String str)"));
			tags.add(new Tag("Encode","css_escapes",true,"css_escapes(String Bstr)"));
			tags.add(new Tag("Encode","css_escapes6",true,"css_escapes6(String str)"));
			tags.add(new Tag("Encode","urlencode",true,"urlencode(String str)"));
            tags.add(new Tag("Encode","urlencode_not_plus",true,"urlencode_not_plus(String str)"));
            tags.add(new Tag("Encode","urlencode_all",true,"urlencode_all(String str)"));
            tags.add(new Tag("Encode","php_non_alpha",true,"php_non_alpha(String input)"));
			tags.add(new Tag("Encode","php_chr",true,"php_chr(String str)"));
			tags.add(new Tag("Encode","sql_hex",true,"sql_hex(String str)"));
            tag = new Tag("Encode","jwt",true,"jwt(String payload, String algo, String secret)");
            tag.argument1 = new TagArgument("string","HS256");
            tag.argument2 = new TagArgument("string","secret");
            tags.add(tag);
			tags.add(new Tag("Decode","auto_decode",true,"auto_decode(String str)"));
			tags.add(new Tag("Decode","d_base32",true,"decode_base32(String str)"));
			tags.add(new Tag("Decode","d_base64",true,"decode_base64(String str)"));
            tags.add(new Tag("Decode","d_base64url",true,"decode_base64url(String str)"));
			tags.add(new Tag("Decode","d_html_entities",true,"decode_html_entities(String str)"));
			tags.add(new Tag("Decode","d_html5_entities",true,"decode_html5_entities(String str)"));
			tags.add(new Tag("Decode","d_js_string",true,"decode_js_string(String str)"));
			tags.add(new Tag("Decode","d_url",true,"decode_url(String str)"));
			tags.add(new Tag("Decode","d_css_escapes",true,"decode_css_escapes(String str)"));
			tags.add(new Tag("Decode","d_octal_escapes",true,"decode_octal_escapes(String str)"));
			tags.add(new Tag("Decode","d_unicode_escapes",true,"decode_js_string(String str)"));
            tags.add(new Tag("Decode","d_jwt_get_payload",true,"d_jwt_get_payload(String token)"));
            tags.add(new Tag("Decode","d_jwt_get_header",true,"d_jwt_get_header(String token)"));
            tag = new Tag("Decode","d_jwt_verify",true,"d_jwt_verify(String token, String secret)");
            tag.argument1 = new TagArgument("string","secret");
            tags.add(tag);
			tag = new Tag("Convert","dec2hex",true,"dec2hex(String str, String splitChar)");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","dec2oct",true,"dec2oct(String str, String splitChar)");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","dec2bin",true,"dec2bin(String str, String splitChar)");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","hex2dec",true,"hex2dec(String str, String splitChar)");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","oct2dec",true,"oct2dec(String str, String splitChar)");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","bin2dec",true,"bin2dec(String str, String splitChar)");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tags.add(new Tag("Convert","ascii2bin",true,"ascii2bin(String str)"));
			tags.add(new Tag("Convert","bin2ascii",true,"bin2ascii(String str)"));
			tag = new Tag("Convert","ascii2hex",true,"ascii2hex(String str, String separator)");
			tag.argument1 = new TagArgument("string"," ");
			tags.add(tag);
			tags.add(new Tag("Convert","hex2ascii",true,"hex2ascii(String str)"));
			tags.add(new Tag("Convert","ascii2reverse_hex",true, "ascii2reverse_hex(String str, String separator)"));
			tags.add(new Tag("String","uppercase",true,"uppercase(String str)"));
			tags.add(new Tag("String","lowercase",true,"lowercase(String str)"));
			tags.add(new Tag("String","capitalise",true,"capitalise(String str)"));
			tags.add(new Tag("String","uncapitalise",true,"uncapitalise(String str)"));
			tags.add(new Tag("String","from_charcode",true,"from_charcode(String str)"));
			tags.add(new Tag("String","to_charcode",true,"to_charcode(String str)"));
			tags.add(new Tag("String","reverse",true,"reverse(String str)"));
            tags.add(new Tag("String","length",true,"len(String str)"));
			tag = new Tag("String","find",true,"find(String str, String find)");
			tag.argument1 = new TagArgument("string","find");
			tags.add(tag);
			tag = new Tag("String","replace",true,"replace(String str, String find, String replace)");
			tag.argument1 = new TagArgument("string","find");
			tag.argument2 = new TagArgument("string","replace");
			tags.add(tag);
			tag = new Tag("String","regex_replace",true,"regex_replace(String str, String find, String replace)");
			tag.argument1 = new TagArgument("string","find");
			tag.argument2 = new TagArgument("string","replace");
			tags.add(tag);
			tag = new Tag("String","repeat",true,"repeat(String str, int amount)");
			tag.argument1 = new TagArgument("int","100");
			tags.add(tag);
			tag = new Tag("String","split_join",true,"split_join(String str, String splitChar, String joinChar)");
			tag.argument1 = new TagArgument("string","split char");
			tag.argument2 = new TagArgument("string","join char");
			tags.add(tag);
			tags.add(new Tag("Hash","sha1",true,"sha1(String str)"));
            tags.add(new Tag("Hash","sha224",true,"sha224(String message)"));
			tags.add(new Tag("Hash","sha256",true,"sha256(String str)"));
			tags.add(new Tag("Hash","sha384",true,"sha384(String str)"));
			tags.add(new Tag("Hash","sha512",true,"sha512(String str)"));
            tags.add(new Tag("Hash","sha3",true,"sha3(String message)"));
            tags.add(new Tag("Hash","sha3_224",true,"sha3_224(String message)"));
            tags.add(new Tag("Hash","sha3_256",true,"sha3_256(String message)"));
            tags.add(new Tag("Hash","sha3_384",true,"sha3_384(String message)"));
            tags.add(new Tag("Hash","sha3_512",true,"sha3_512(String message)"));
            tags.add(new Tag("Hash","skein_256_128",true,"skein_256_128(String message)"));
            tags.add(new Tag("Hash","skein_256_160",true,"skein_256_160(String message)"));
            tags.add(new Tag("Hash","skein_256_224",true,"skein_256_224(String message)"));
            tags.add(new Tag("Hash","skein_256_256",true,"skein_256_256(String message)"));
            tags.add(new Tag("Hash","skein_512_128",true,"skein_512_128(String message)"));
            tags.add(new Tag("Hash","skein_512_160",true,"skein_512_160(String message)"));
            tags.add(new Tag("Hash","skein_512_224",true,"skein_512_224(String message)"));
            tags.add(new Tag("Hash","skein_512_256",true,"skein_512_256(String message)"));
            tags.add(new Tag("Hash","skein_512_384",true,"skein_512_384(String message)"));
            tags.add(new Tag("Hash","skein_512_512",true,"skein_512_512(String message)"));
            tags.add(new Tag("Hash","skein_1024_384",true,"skein_1024_384(String message)"));
            tags.add(new Tag("Hash","skein_1024_512",true,"skein_1024_512(String message)"));
            tags.add(new Tag("Hash","skein_1024_1024",true,"skein_1024_1024(String message)"));
            tags.add(new Tag("Hash","sm3",true,"sm3(String message)"));
            tags.add(new Tag("Hash","tiger",true,"tiger(String message)"));
			tags.add(new Tag("Hash","md2",true,"md2(String str)"));
            tags.add(new Tag("Hash","md4",true,"md4(String message)"));
			tags.add(new Tag("Hash","md5",true,"md5(String str)"));
            tags.add(new Tag("Hash","gost3411",true,"gost3411(String message)"));
            tags.add(new Tag("Hash","ripemd128",true,"ripemd128(String message)"));
            tags.add(new Tag("Hash","ripemd160",true,"ripemd160(String message)"));
            tags.add(new Tag("Hash","ripemd256",true,"ripemd256(String message)"));
            tags.add(new Tag("Hash","ripemd320",true,"ripemd320(String message)"));
            tags.add(new Tag("Hash","whirlpool",true,"whirlpool(String message)"));
			tag = new Tag("Math","range",true,"range(String str, int from, int to, int step)");
			tag.argument1 = new TagArgument("int","0");
			tag.argument2 = new TagArgument("int","100");
			tag.argument3 = new TagArgument("int","1");
			tags.add(tag);
			tags.add(new Tag("Math","total",true,"total(String str)"));
			tag = new Tag("Math","arithmetic",true,"arithmetic(String str, int amount, String operation, String splitChar)");
			tag.argument1 = new TagArgument("int","10");
			tag.argument2 = new TagArgument("string","+");
			tag.argument3 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Math","convert_base",true,"convert_base(String str, String splitChar, int from, int to)");
			tag.argument1 = new TagArgument("string",",");
			tag.argument2 = new TagArgument("int","from");
			tag.argument3 = new TagArgument("int","to");
			tags.add(tag);
            tag = new Tag("Math","random",true,"random(String chars, int len)");
            tag.argument1 = new TagArgument("int","10");
            tags.add(tag);
            tag = new Tag("Math","random_unicode",false,"random_unicode(int from, int to, int amount)");
            tag.argument1 = new TagArgument("int","0");
            tag.argument2 = new TagArgument("int","0xffff");
            tag.argument3 = new TagArgument("int","100");
            tags.add(tag);
			tag = new Tag("Math","zeropad",true,"zeropad(String str, String splitChar, int amount)");
			tag.argument1 = new TagArgument("string",",");
			tag.argument2 = new TagArgument("int","2");
			tags.add(tag);
			tags.add(new Tag("XSS","behavior",true,"behavior(String str)"));
			tags.add(new Tag("XSS","css_expression",true,"css_expression(String str)"));
			tags.add(new Tag("XSS","datasrc",true,"datasrc(String str)"));
			tags.add(new Tag("XSS","eval_fromcharcode",true,"eval_fromcharcode(String str)"));
			tags.add(new Tag("XSS","iframe_data_url",true,"iframe_data_url(String str)"));
			tags.add(new Tag("XSS","iframe_src_doc",true,"iframe_src_doc(String str)"));
			tags.add(new Tag("XSS","script_data",true,"script_data(String str)"));
			tags.add(new Tag("XSS","uppercase_script",true,"uppercase_script(String str)"));
			tags.add(new Tag("XSS","template_eval",true,"template_eval(String str)"));
            tags.add(new Tag("XSS","throw_eval",true,"throw_eval(String str)"));
		}
		String convertCharset(String input, String to) {
            String output = "";
            try {
                return helpers.bytesToString(input.getBytes(to));
            } catch (UnsupportedEncodingException e) {
                return e.toString();
            }
        }
        String charset_convert(String input, String from, String to) {
            byte[] inputBytes = input.getBytes();
            byte[] output = new byte[0];
            try {
                output = new String(inputBytes, from).getBytes(to);
            } catch (UnsupportedEncodingException e) {
                return e.toString();
            }
            return helpers.bytesToString(output);
        }
		String utf16(String input) {
            return convertCharset(input, "UTF-16");
        }
        String utf16be(String input) {
            return convertCharset(input, "UTF-16BE");
        }
        String utf16le(String input) {
            return convertCharset(input, "UTF-16LE");
        }
        String utf32(String input) {
            return convertCharset(input, "UTF-32");
        }
        String shift_jis(String input) {
            return convertCharset(input, "SHIFT_JIS");
        }
        String gb2312(String input) {
            return convertCharset(input, "GB2312");
        }
        String euc_kr(String input) {
            return convertCharset(input, "EUC-KR");
        }
        String euc_jp(String input) {
            return convertCharset(input, "EUC-JP");
        }
        String gbk(String input) {
            return convertCharset(input, "GBK");
        }
        String big5(String input) {
            return convertCharset(input, "BIG5");
        }
        String gzip_compress(String input) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
            GZIPOutputStream gzip = null;
            try {
                gzip = new GZIPOutputStream(bos);
                gzip.write(input.getBytes());
                gzip.close();
                byte[] compressed = bos.toByteArray();
                bos.close();
                return helpers.bytesToString(compressed);
            } catch (IOException e) {
                e.printStackTrace();
                return "Error:"+e.toString();
            }
        }
        String gzip_decompress(String input) {
            ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
            GZIPInputStream gis = null;
            byte[] bytes;
            try {
                gis = new GZIPInputStream(bis);
                bytes = IOUtils.toByteArray(gis);
                return new String(bytes);
            } catch (IOException e) {
                e.printStackTrace();
                return "Error:"+e.toString();
            }
        }
        String bzip2_compress(String input) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
            CompressorOutputStream cos = null;
            try {
                cos = new CompressorStreamFactory()
                        .createCompressorOutputStream(CompressorStreamFactory.getBzip2(), bos);
            } catch (CompressorException e) {
                e.printStackTrace();
                return "Error creating compressor:"+e.toString();
            }
            try {
                cos.write(input.getBytes());
                cos.close();
                byte[] compressed = bos.toByteArray();
                bos.close();
                return helpers.bytesToString(compressed);
            } catch (IOException e) {
                e.printStackTrace();
                return "Error:"+e.toString();
            }
        }
        String bzip2_decompress(String input) {
            ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
            BZip2CompressorInputStream cis = null;
            byte[] bytes;
            try {
                cis = new BZip2CompressorInputStream(bis);
                bytes = IOUtils.toByteArray(cis);
                return new String(bytes);
            } catch (IOException e) {
                e.printStackTrace();
                return "Error:"+e.toString();
            }
        }
        String deflate_compress(String input) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(input.length());
            CompressorOutputStream cos = null;
            try {
                cos = new CompressorStreamFactory()
                        .createCompressorOutputStream(CompressorStreamFactory.getDeflate(), bos);
            } catch (CompressorException e) {
                e.printStackTrace();
                return "Error creating compressor:"+e.toString();
            }
            try {
                cos.write(input.getBytes());
                cos.close();
                byte[] compressed = bos.toByteArray();
                bos.close();
                return helpers.bytesToString(compressed);
            } catch (IOException e) {
                e.printStackTrace();
                return "Error:"+e.toString();
            }
        }
        String deflate_decompress(String input) {
            ByteArrayInputStream bis = new ByteArrayInputStream(helpers.stringToBytes(input));
            DeflateCompressorInputStream cis = null;
            byte[] bytes;
            try {
                cis = new DeflateCompressorInputStream(bis);
                bytes = IOUtils.toByteArray(cis);
                return new String(bytes);
            } catch (IOException e) {
                e.printStackTrace();
                return "Error:"+e.toString();
            }
        }
		String html_entities(String str) {
            return HtmlEscape.escapeHtml(str, HtmlEscapeType.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
		}
		String decode_html_entities(String str) {
            return HtmlEscape.unescapeHtml(str);
		}
		String base32_encode(String str) {
			Base32 base32 = new Base32();
	        return new String(base32.encode(str.getBytes()));
		}
		String decode_base32(String str) {
			Base32 base32 = new Base32();
			return new String(base32.decode(str.getBytes()));
		}
		String base64Encode(String str) {
			return helpers.base64Encode(str);
		}
		String decode_base64(String str) {
			try{
				str = helpers.bytesToString(helpers.base64Decode(str));
			} catch(Exception e){ 
				stderr.println(e.getMessage());
			}
			return str;
		}
        String base64urlEncode(String str) {
            return base64Encode(str).replaceAll("\\+","-").replaceAll("/","_").replaceAll("=+$","");
        }
        String decode_base64url(String str) {
            str = str.replaceAll("-","+");
            str = str.replaceAll("_","/");
            switch (str.length() % 4) {
                case 0: break;
                case 2: str += "=="; break;
                case 3: str += "="; break;
            }
            return helpers.bytesToString(helpers.base64Decode(str));
        }
		String urlencode(String str) {
			try {
	            str = URLEncoder.encode(str, "UTF-8");		    
	        } catch (Exception e) {
	        	stderr.println(e.getMessage());
	        }
			return str;
		}
        String urlencode_not_plus(String str) {
            try {
                str = URLEncoder.encode(str, "UTF-8").replaceAll("\\+","%20");
            } catch (Exception e) {
                stderr.println(e.getMessage());
            }
            return str;
        }
        String urlencode_all(String str) {
            StringBuilder converted = new StringBuilder();
            for(int i=0;i<str.length();i++) {
                int codePoint = Character.codePointAt(str, i);
                if(codePoint<=0xff) {
                    converted.append("%" + Integer.toHexString(codePoint));
                } else {
                    try {
                        converted.append(URLEncoder.encode(Character.toString(str.charAt(i)), "UTF-8"));
                    } catch (Exception e) {
                        stderr.println(e.getMessage());
                    }
                }
            }
            return converted.toString();
        }
		String decode_url(String str) {
			try {
	            str = URLDecoder.decode(str, "UTF-8");		          
	        } catch (Exception e) {
	        	stderr.println(e.getMessage());
	        }
			return str;
		}
        String random(String chars, int len) {
            if(len > 0 && chars.length() > 0) {
                StringBuilder sb = new StringBuilder();
                Random random = new Random();
                for (int i = 0; i < len; i++) {
                    sb.append(chars.charAt(random.nextInt(chars.length())));
                }
                return sb.toString();
            }
            return "";
        }
        String random_unicode(int from, int to, int amount) {
            String out = "";
            try {
                for (int i = 0; i < amount; i++) {
                   Random random = new Random();
                    int  n = random.nextInt(to) + from;
                    out += (char) n;
                }
                return out;
            } catch(Exception e) {
                return "Unable to create unicode characters";
            }
        }
		String uppercase(String str) {
			return StringUtils.upperCase(str);
		}
		String lowercase(String str) {
			return StringUtils.lowerCase(str);
		}
		String capitalise(String str) {
			return StringUtils.capitalize(str);
		}
		String uncapitalise(String str) {
			return StringUtils.uncapitalize(str);
		}
		String html5_entities(String str) {
			return HtmlEscape.escapeHtml(str, HtmlEscapeType.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
		}
		String decode_html5_entities(String str) {
			return HtmlEscape.unescapeHtml(str);
		}
        String hex(String str, String separator) {
            return ascii2hex(str,separator);
        }
		String hex_entities(String str) {
			return HtmlEscape.escapeHtml(str, HtmlEscapeType.HEXADECIMAL_REFERENCES,HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		String dec_entities(String str) {
			return HtmlEscape.escapeHtml(str, HtmlEscapeType.DECIMAL_REFERENCES,HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		String jwt(String payload, String algo, String secret) {
            try {
                algo = algo.toUpperCase();
                String algoName;
                if(algo.equals("HS256")) {
                    algoName = "HmacSHA256";
                } else if(algo.equals("HS384")) {
                    algoName = "HmacSHA384";
                } else if(algo.equals("HS512")) {
                    algoName = "HmacSHA512";
                } else {
                    return "Unsupported algorithm";
                }
                Mac hashMac = Mac.getInstance(algoName);
                String message = "";
                String header = "{\n" +
                        "  \"alg\": \""+algo+"\",\n" +
                        "  \"typ\": \"JWT\"\n" +
                        "}";
                message = base64urlEncode(header) + "." + base64urlEncode(payload);
                SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), algoName);
                hashMac.init(secret_key);
                return message + "." + base64urlEncode(helpers.bytesToString(hashMac.doFinal(message.getBytes())));
            } catch (Exception e){
                return "Unable to create token";
            }
        }
        String d_jwt_get_payload(String token) {
            try {
                DecodedJWT jwt = JWT.decode(token);
                return decode_base64url(jwt.getPayload());
            } catch (JWTDecodeException exception){
                return "Invalid token";
            }
        }
        String d_jwt_get_header(String token) {
            try {
                DecodedJWT jwt = JWT.decode(token);
                return decode_base64url(jwt.getHeader());
            } catch (JWTDecodeException exception){
                return "Invalid token";
            }
        }
        String d_jwt_verify(String token, String secret) {
            DecodedJWT jwt;
            try {
                jwt = JWT.decode(token);
            } catch (JWTDecodeException exception){
                return "Invalid token";
            }
            try {
                String algo = jwt.getAlgorithm().toUpperCase();
                Algorithm algorithm = null;
                if(algo.equals("HS256")) {
                    algorithm = Algorithm.HMAC256(secret);
                } else if(algo.equals("HS384")) {
                    algorithm = Algorithm.HMAC384(secret);
                } else if(algo.equals("HS512")) {
                    algorithm = Algorithm.HMAC512(secret);
                } else {
                    return "0";
                }
                JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer(jwt.getIssuer())
                        .build();
                verifier.verify(token);
                return "1";
            } catch (IllegalArgumentException e) {
                return "0";
            } catch (Exception exception) {
                return "0";
            }
        }
		String hex_escapes(String str) {
			return JavaScriptEscape.escapeJavaScript(str,JavaScriptEscapeType.XHEXA_DEFAULT_TO_UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		String octal_escapes(String str) {
			StringBuilder converted = new StringBuilder();
			for(int i=0;i<str.length();i++) {
				converted.append("\\" + Integer.toOctalString(Character.codePointAt(str, i)));
			}
			return converted.toString();
		}
		String decode_octal_escapes(String str) {
			return this.decode_js_string(str);
		}
		String css_escapes(String str) {
			return CssEscape.escapeCssString(str,CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		String css_escapes6(String str) {
			return CssEscape.escapeCssString(str,CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		String unicode_escapes(String str) {
			return JavaScriptEscape.escapeJavaScript(str,JavaScriptEscapeType.UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		String php_non_alpha(String input) {
                String converted = "";
                converted += "$_[]++;$_[]=$_._;";
                converted += "$_____=$_[(++$__[])][(++$__[])+(++$__[])+(++$__[])];";
                converted += "$_=$_[$_[+_]];";
                converted += "$___=$__=$_[++$__[]];";
                converted += "$____=$_=$_[+_];";
                converted += "$_++;$_++;$_++;";
                converted += "$_=$____.++$___.$___.++$_.$__.++$___;";
                converted += "$__=$_;";
                converted += "$_=$_____;";
                converted += "$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;$_++;";
                converted += "$___=+_;";
                converted += "$___.=$__;";
                converted += "$___=++$_^$___[+_];$\u00c0=+_;$\u00c1=$\u00c2=$\u00c3=$\u00c4=$\u00c6=$\u00c8=$\u00c9=$\u00ca=$\u00cb=++$\u00c1[];";
                converted += "$\u00c2++;";
                converted += "$\u00c3++;$\u00c3++;";
                converted += "$\u00c4++;$\u00c4++;$\u00c4++;";
                converted += "$\u00c6++;$\u00c6++;$\u00c6++;$\u00c6++;";
                converted += "$\u00c8++;$\u00c8++;$\u00c8++;$\u00c8++;$\u00c8++;";
                converted += "$\u00c9++;$\u00c9++;$\u00c9++;$\u00c9++;$\u00c9++;$\u00c9++;";
                converted += "$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;$\u00ca++;";
                converted += "$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;$\u00cb++;";
                converted += "$__('$_=\"'";
                String[] lookup = {"\u00c0","\u00c1","\u00c2","\u00c3","\u00c4","\u00c6","\u00c8","\u00c9","\u00ca","\u00cb"};
                for(int i=0;i<input.length();i++) {
                    ArrayList<String> vars = new ArrayList<String>();
                    String chrs = Integer.toOctalString(Character.codePointAt(input, i)).toString();
                    for(int j=0;j<chrs.length();j++) {
                        vars.add("$"+lookup[Integer.parseInt(chrs.charAt(j)+"")]);
                    }
                    converted += ".$___."+StringUtils.join(vars,".");
                }
                converted += ".'";
                converted += "\"');$__($_);";
                return "<?php "+converted+"?>";
        }
		String php_chr(String str) {
			ArrayList<String> output = new ArrayList<String>();
			for(int i=0;i<str.length();i++) {
				output.add("chr("+Character.codePointAt(str, i)+")");
			}
			return StringUtils.join(output,".");
		}
		String sql_hex(String str) {
			return "0x"+this.ascii2hex(str, "");
		}
        String rotN(String str, int n) {
            String out = "";
            int len = str.length();
            for(int i=0;i<len;i++) {
                char chr = str.charAt(i);
                int chrCode = (int) chr;
                if(Character.isLowerCase(chr)) {
                    out += (char) ((chrCode-97+n)%26+97);
                } else if(Character.isUpperCase(str.charAt(i))) {
                    out += (char) ((chrCode-65+n)%26+65);
                } else {
                    out += chr;
                }
            }
            return out;
        }
        String xor(String message, String key) {
            try {
                int len = message.length();
                int keyLen = key.length();
                StringBuilder output = new StringBuilder();
                for (int i = 0; i < len; i++) {
                    output.append((char) (message.charAt(i) ^ key.charAt(i % keyLen)));
                }
                return output.toString();
            } catch (Exception e) {
                return "Unable to encode";
            }
        }
        int guess_key_length(String ciphertext) {
            int max = 30;
            TreeMap<Integer,Double> totalIC = new TreeMap<Integer,Double>();
            TreeMap<Integer,Double> normalizedIC = new TreeMap<Integer,Double>();
            for(int candidateLength=2;candidateLength<=max;candidateLength++) {
                double[][] frequencies = new double[256][max+1];
                for(int pos=0;pos<ciphertext.length();pos++) {
                    int column = pos % candidateLength;
                    frequencies[ciphertext.codePointAt(pos)][column] += 1;
                }

                double[] lengthN = new double[max+1];
                for(int column=0;column<candidateLength;column++) {
                    for(int character=0;character<=255;character++) {
                        lengthN[column] += frequencies[character][column];
                    }
                }
                for(int column=0;column<candidateLength;column++) {
                    for (int character = 0; character <= 255; character++) {
                        frequencies[character][column] *= frequencies[character][column] * (frequencies[character][column] - 1);
                    }
                }
                double[] frequencySum = new double[max+1];
                for(int column=0;column<candidateLength;column++) {
                    for (int character = 0; character <= 255; character++) {
                        frequencySum[column] += frequencies[character][column];
                    }
                }
                double[] columnIC = new double[max+1];
                for(int column=0;column<candidateLength;column++) {
                    if(lengthN[column] > 1) {
                        columnIC[column] = frequencySum[column] / (lengthN[column] * (lengthN[column] - 1.0));
                    }
                }
                double ic = 0;
                for(int column=0;column<candidateLength;column++) {
                    ic += columnIC[column];
                }
                totalIC.put(candidateLength,ic);
            }
            Map sortedMap = sortByValuesDesc(totalIC);
            Iterator it = sortedMap.entrySet().iterator();
            int pos = 0;
            while (it.hasNext()) {
                if(pos > 8) {
                    break;
                }
                Map.Entry pair = (Map.Entry)it.next();
                int key = (int) pair.getKey();
                normalizedIC.put(key, (double) pair.getValue()/key);
                pos++;
            }
            sortedMap = sortByValuesDesc(normalizedIC);
            it = sortedMap.entrySet().iterator();
            Map.Entry pair = (Map.Entry)it.next();
            return (int) pair.getKey();
        }
        int getScore(char clearTextByte) {
            int score = 0;
            if(clearTextByte >= ' ' && clearTextByte < '\u00ff') {
                score += 1;
            }
            if ((clearTextByte >= 'A') && (clearTextByte <= 'Z')){
                score += 1;
            }
            if ((clearTextByte >= 'a') && (clearTextByte <= 'z')) {
                score += 2;
            }
            if (clearTextByte == ' ') {
                score += 5;
            }
            if (clearTextByte == ',') {
                score += 2;
            }
            if ((clearTextByte == '.') || (clearTextByte == '!') ||
                    (clearTextByte == ';') || (clearTextByte == '?')) {
                score += 1;
            }
            return score;
        }
        String xor_decrypt(String ciphertext, int keyLength, boolean returnKey) {
            if(Pattern.compile("^[0-9a-fA-F]+$").matcher(ciphertext).find()) {
                ciphertext = this.hex2ascii(ciphertext);
            }
            String[] guessedKey = new String[keyLength];
            for(int column = 0; column < keyLength; column++) {
                double maxScore = 0;
                for(int keyByte=0;keyByte<=255;keyByte++) {
                    int score = 0;
                    for(int pos=0;pos<ciphertext.length();pos++) {
                        if((pos - column) % keyLength == 0) {
                            char clearTextByte = (char) (ciphertext.charAt(pos) ^ (char) keyByte);
                            score += getScore(clearTextByte);
                        }
                    }
                    if(score > maxScore) {
                        maxScore = score;
                        guessedKey[column] = "" + (char) keyByte;
                    }
                }
            }
            if(returnKey) {
                return StringUtils.join(guessedKey, "");
            } else {
                return xor(ciphertext, StringUtils.join(guessedKey, ""));
            }
        }
        String xor_getkey(String ciphertext) {
            int len = guess_key_length(ciphertext);
            return xor_decrypt(ciphertext, len, true);
        }
        String affine_encrypt(String message, int key1, int key2) {
            int[] keyArray1 = {1,3,5,7,9,11,15,17,19,21,23,25};
            int[] keyArray2 = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25};
            String encoded = "";
            if(!IntStream.of(keyArray1).anyMatch(x -> x == key1)) {
                return "Invalid key1 must be one of:1,3,5,7,9,11,15,17,19,21,23,25";
            }
            if(!IntStream.of(keyArray2).anyMatch(x -> x == key2)) {
                return "Invalid key2 must be one of:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25";
            }
            message = message.toLowerCase();
            for(int i=0;i<message.length();i++) {
                char chr = message.charAt(i);
                if(Character.isLowerCase(chr)) {
                    int chrCode = Character.codePointAt(message, i) - 97;
                    int newChrCode = ((key1 * chrCode + key2) % 26) + 97;
                    encoded += (char) newChrCode;
                } else {
                    encoded += chr;
                }
            }
            return encoded;
        }
        String affine_decrypt(String ciphertext, int key1, int key2) {
            int[] keyArray1 = {1,3,5,7,9,11,15,17,19,21,23,25};
            int[] keyArray2 = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25};
            String plaintext = "";
            if(!IntStream.of(keyArray1).anyMatch(x -> x == key1)) {
                return "Invalid key1 must be one of:1,3,5,7,9,11,15,17,19,21,23,25";
            }
            if(!IntStream.of(keyArray2).anyMatch(x -> x == key2)) {
                return "Invalid key2 must be one of:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25";
            }
            int multinverse = 1;
            for (int i = 1; i <= 25; i = i + 2) {
                if ((key1 * i) % 26 == 1) {
                    multinverse = i;
                }
            }
            for(int i=0;i<ciphertext.length();i++) {
                char chr = ciphertext.charAt(i);
                if(Character.isLowerCase(chr)) {
                    int chrCode = Character.codePointAt(ciphertext, i) - 97;
                    int newChrCode = ((multinverse * (chrCode + 26 - key2)) % 26) + 97;
                    plaintext += (char) newChrCode;
                } else {
                    plaintext += chr;
                }
            }
            return plaintext;
        }
        String atbash_encrypt(String message) {
            message = message.toLowerCase();
            String encoded = "";
            String key = "ZYXWVUTSRQPONMLKJIHGFEDCBA".toLowerCase();
            for(int i=0;i<message.length();i++) {
                char chr = message.charAt(i);
                if(Character.isLowerCase(chr)) {
                    encoded += key.charAt(message.codePointAt(i)-97);
                } else {
                    encoded += chr;
                }
            }
            return encoded;
        }
        String atbash_decrypt(String ciphertext) {
            ciphertext = ciphertext.toLowerCase();
            String plaintext = "";
            String key = "ZYXWVUTSRQPONMLKJIHGFEDCBA".toLowerCase();
            for(int i=0;i<ciphertext.length();i++) {
                char chr = ciphertext.charAt(i);
                if(Character.isLowerCase(chr)) {
                    plaintext += (char) (key.indexOf(ciphertext.charAt(i))+97);
                } else {
                    plaintext += chr;
                }
            }
            return plaintext;
        }
        String rotN_bruteforce(String str) {
            String out = "";
            for(int i = 1; i <= 25;i++) {
                out += i + "=" + rotN(str, i) + "\n";
            }
            return out;
        }
        String rail_fence_encrypt(String message, int key) {
            String ciphertext = "";
            message = message.toLowerCase().replaceAll("[^a-z]","");
            if(key < 1) {
                return "";
            }
            if(message.length() < 1) {
                return "";
            }
            if(key > Math.floor(2*message.length()-1)) {
                return "Error: key is too large for plaintext length";
            }
            if(key == 1) {
                return message;
            } else {
                int line = 0;
                for(line=0;line<key-1;line++) {
                    int skip = 2 * (key-line-1);
                    int j = 0;
                    for(int i=line;i<message.length();) {
                        ciphertext += message.charAt(i);
                        if((line == 0) || (j % 2 == 0)) {
                            i+=skip;
                        } else {
                            i += 2 * (key - 1) - skip;
                        }
                        j++;
                    }
                }
                for(int i = line; i < message.length(); i += 2 *(key-1)) {
                    ciphertext += message.charAt(i);
                }
                return ciphertext;
            }

        }
        String rail_fence_decrypt(String encoded, int key) {
            String plaintext = "";
            encoded = encoded.toLowerCase().replaceAll("[^a-z]","");
            if(key < 1) {
                return "";
            }
            if(encoded.length() < 1) {
                return "";
            }
            if(key > Math.floor(2*encoded.length()-1)) {
                return "Error: key is too large for plaintext length";
            }
            if(key == 1) {
                return encoded;
            } else {
                String[] pt = new String[encoded.length()];
                int k = 0;
                int line = 0;
                for(line = 0;line<key-1;line++) {
                    int skip = 2 * (key-line-1);
                    int j = 0;
                    for(int i=line;i<encoded.length();) {
                        pt[i] = "" + encoded.charAt(k++);
                        if((line == 0) || (j % 2 == 0)) {
                            i += skip;
                        } else {
                            i += 2 * (key - 1) - skip;
                        }
                        j++;
                    }
                }
                for(int i=line; i < encoded.length(); i += 2 * (key -1)) {
                    pt[i] = "" + encoded.charAt(k++);
                }
                plaintext = String.join("", pt);
            }
            return plaintext;
        }
        String substitution_encrypt(String message, String key) {
            String ciphertext = "";
            message = message.toLowerCase();
            key = key.replaceAll("[^a-z]","");
            if(key.length() != 26) {
                return "Error: Key length must be 26 characters";
            }
            if(message.length() < 1) {
                return "";
            }
            for(int i=0;i<message.length();i++) {
                char chr = message.charAt(i);
                if(Character.isLowerCase(chr)) {
                    ciphertext += key.charAt(message.codePointAt(i)-97);
                } else {
                    ciphertext += "" + chr;
                }
            }
            return ciphertext;
        }
        String substitution_decrypt(String ciphertext, String key) {
            ciphertext = ciphertext.toLowerCase();
            String plaintext = "";
            key = key.toLowerCase().replaceAll("[^a-z]","");
            if(key.length() != 26) {
                return "Error: Key length must be 26 characters";
            }
            if(ciphertext.length() < 1) {
                return "";
            }
            for(int i=0;i<ciphertext.length();i++) {
                char chr = ciphertext.charAt(i);
                if(Character.isLowerCase(chr)) {
                    plaintext += (char) (key.indexOf(ciphertext.charAt(i)) + 97);
                } else {
                    plaintext += ciphertext.charAt(i);
                }
            }
            return plaintext;
        }
		String decode_js_string(String str) {
			return JavaScriptEscape.unescapeJavaScript(str);
		}
		String decode_css_escapes(String str) {
			return CssEscape.unescapeCss(str);
		}
		String dec2hex(String str, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = this.zeropad(Integer.toHexString(Integer.parseInt(chars[i])),",",2);	
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String dec2oct(String str, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}		
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = Integer.toOctalString(Integer.parseInt(chars[i]));	
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String dec2bin(String str, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}		
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = Integer.toBinaryString(Integer.parseInt(chars[i]));	
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String hex2dec(String str, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}		
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = Integer.toString(Integer.parseInt(chars[i],16));	
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String oct2dec(String str, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}		
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = Integer.toString(Integer.parseInt(chars[i],8));	
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String bin2dec(String str, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}		
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = Integer.toString(Integer.parseInt(chars[i],2));	
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String from_charcode(String str) {
		   String[] chars = str.split("[\\s,]");
		   String output = "";	   
		   for(int i=0;i<chars.length;i++) {
			   try {
				   output += Character.toString((char) Integer.parseInt(chars[i]));
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
		   }
		   return output;
		}
		String to_charcode(String str) {
			ArrayList<Integer> output = new ArrayList<Integer>();
			for(int i=0;i<str.length();i++) {
				output.add(Character.codePointAt(str, i));
			}
			return StringUtils.join(output,",");
		}
		String ascii2bin(String str) {
			String output = "";
			for(int i=0;i<str.length();i++) {
			   try {
				   output += Integer.toBinaryString(Character.codePointAt(str, i));
				   output += " ";
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
		   }
			return output;
		}
		String bin2ascii(String str) {
			String[] chars = str.split(" ");
			String output = "";
			for(int i=0;i<chars.length;i++) {
				   try {
					   output += Character.toString((char) Integer.parseInt(chars[i],2));
				   } catch(NumberFormatException e){ 
						stderr.println(e.getMessage()); 
				   }
			   }
			return output;
		}
		String ascii2hex(String str, String separator) {
			String output = "";
			String hex = "";
			for(int i=0;i<str.length();i++) {
			   try {
				   hex = Integer.toHexString(Character.codePointAt(str, i));
				   if(hex.length() % 2 != 0) {
					   hex = "0" + hex;
				   }
				   output += hex;
				   if(separator.length() > 0 && i < str.length()-1) {
					   output += separator;
				   }
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
			}
			return output;
		}
		String ascii2reverse_hex(String str, String separator) {
			String hex = "";
			List<String> output = new ArrayList<>();
			for(int i=0;i<str.length();i++) {
			   try {
				   hex = Integer.toHexString(Character.codePointAt(str, i));
				   if(hex.length() % 2 != 0) {
					   hex = "0" + hex;
				   }
				   output.add(hex);				
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
			}
			Collections.reverse(output);
			return StringUtils.join(output,"");
		}		
		String hex2ascii(String str) {
            Pattern p = Pattern.compile("([0-9a-fA-F]{2})(?:[\\s,\\-]?)");
            Matcher m = p.matcher(str);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                m.appendReplacement(sb, "");
                sb.append(Character.toString((char) Integer.parseInt(m.group(1),16)));
            }
            return sb.toString();
		}
		String sha1(String str) {
			return DigestUtils.sha1Hex(str);
		}
        String sha224(String message) {
            SHA224Digest digest = new SHA224Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
		String sha256(String str) {
			return DigestUtils.sha256Hex(str);
		}
		String sha384(String str) {
			return DigestUtils.sha384Hex(str);
		}
		String sha512(String str) {
			return DigestUtils.sha512Hex(str);
		}
        String sha3(String message) {
            SHA3Digest digest = new SHA3Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String sha3_224(String message) {
            SHA3Digest digest = new SHA3Digest(224);
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String sha3_256(String message) {
            SHA3Digest digest = new SHA3Digest(256);
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String sha3_384(String message) {
            SHA3Digest digest = new SHA3Digest(384);
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String sha3_512(String message) {
            SHA3Digest digest = new SHA3Digest(512);
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String skein_256_128(String message) {
            Skein.Digest_256_128 digest = new Skein.Digest_256_128();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_256_160(String message) {
            Skein.Digest_256_160 digest = new Skein.Digest_256_160();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_256_224(String message) {
            Skein.Digest_256_224 digest = new Skein.Digest_256_224();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_256_256(String message) {
            Skein.Digest_256_256 digest = new Skein.Digest_256_256();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_512_128(String message) {
            Skein.Digest_512_128 digest = new Skein.Digest_512_128();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_512_160(String message) {
            Skein.Digest_512_160 digest = new Skein.Digest_512_160();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_512_224(String message) {
            Skein.Digest_512_224 digest = new Skein.Digest_512_224();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_512_256(String message) {
            Skein.Digest_512_256 digest = new Skein.Digest_512_256();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_512_384(String message) {
            Skein.Digest_512_384 digest = new Skein.Digest_512_384();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_512_512(String message) {
            Skein.Digest_512_512 digest = new Skein.Digest_512_512();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_1024_384(String message) {
            Skein.Digest_1024_384 digest = new Skein.Digest_1024_384();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_1024_512(String message) {
            Skein.Digest_1024_512 digest = new Skein.Digest_1024_512();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String skein_1024_1024(String message) {
            Skein.Digest_1024_1024 digest = new Skein.Digest_1024_1024();
            digest.update(message.getBytes(),0,message.getBytes().length);
            return org.bouncycastle.util.encoders.Hex.toHexString(digest.digest());
        }
        String sm3(String message) {
            SM3Digest digest = new SM3Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String tiger(String message) {
            TigerDigest digest = new TigerDigest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
		String md2(String str) {
			return DigestUtils.md2Hex(str);
		}
		String md5(String str) {
            return DigestUtils.md5Hex(str);
        }
        String md4(String message) {
            MD4Digest digest = new MD4Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] md4Bytes = new byte[digest.getDigestSize()];
            digest.doFinal(md4Bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes);
        }
        String gost3411(String message) {
            GOST3411Digest digest = new GOST3411Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String ripemd128(String message) {
            RIPEMD128Digest digest = new RIPEMD128Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String ripemd160(String message) {
            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String ripemd256(String message) {
            RIPEMD256Digest digest = new RIPEMD256Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String ripemd320(String message) {
            RIPEMD320Digest digest = new RIPEMD320Digest();
            digest.update(message.getBytes(),0,message.getBytes().length);
            byte[] bytes = new byte[digest.getDigestSize()];
            digest.doFinal(bytes, 0);
            return org.bouncycastle.util.encoders.Hex.toHexString(bytes);
        }
        String whirlpool(String message) {
            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance("WHIRLPOOL", "BC");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }
            byte[] result = digest.digest(message.getBytes());
            return new String(Hex.encode(result));
        }
		String reverse(String str) {
			return new StringBuilder(str).reverse().toString();
		}
        String len(String str) {
            return Integer.toString(str.length());
        }
		String find(String str, String find) {
			List<String> allMatches = new ArrayList<String>();
			 try {
				 Matcher m = Pattern.compile(find).matcher(str);
				 while (m.find()) {
				   allMatches.add(m.group());
				 }
			 } catch(PatternSyntaxException e) {
				 stderr.println(e.getMessage());
			 }
			 return StringUtils.join(allMatches,",");
		}
		String replace(String str, String find, String replace) {
			return str.replace(find, replace);
		}
		String regex_replace(String str, String find, String replace) {
			String output = "";
			try {
				output = str.replaceAll(find, replace.replace("\\","\\\\").replace("$","\\$"));
			} catch(PatternSyntaxException e) {
				 stderr.println(e.getMessage());
			}
			return output;
		}
		String repeat(String str, int amount) {
			String output = "";
			if(amount > 0 && amount < 10000) {
				for(int i=0;i<amount;i++) {
					output += str;
				}
			}
			return output;
		}
		String split_join(String str, String splitChar, String joinChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			return StringUtils.join(chars, joinChar);
		}
		double is_like_english(String str) {
            ngrams.setInput(str);
            return ngrams.getScore();
        }
        double index_of_coincidence(String str) {
            Map<Integer,Integer> charCounter=new HashMap<Integer,Integer>();
            for(int i=0;i<=0xff;i++) {
                charCounter.put(i, 0);
            }
            for(int i=0;i<str.length();i++) {
                int cp = str.codePointAt(i);
                charCounter.put(cp, charCounter.get(cp)+1);

            }
            double sum = 0;
            int total = str.length();
            for(int i=0;i<=0xff;i++) {
                sum = sum + charCounter.get(i) * (i -1 < 0 ? 0 : charCounter.get(i-1));
            }
            double ic = sum / (total * (total - 1));
            return ic;
        }
        int getGCD(int n1, int n2) {
            if(n2 == 0) {
                return n1;
            }
            return getGCD(n2, n1 % n2);
        }
        <K, V extends Comparable<V>> Map<K, V>
        sortByValuesDesc(final Map<K, V> map) {
            Comparator<K> valueComparator =
                    new Comparator<K>() {
                        public int compare(K k1, K k2) {
                            int compare =
                                    map.get(k2).compareTo(map.get(k1));
                            if (compare == 0)
                                return 1;
                            else
                                return compare;
                        }
                    };

            Map<K, V> sortedByValues =
                    new TreeMap<K, V>(valueComparator);
            sortedByValues.putAll(map);
            return sortedByValues;
        }
        <K, V extends Comparable<V>> Map<K, V>
        sortByValuesAsc(final Map<K, V> map) {
            Comparator<K> valueComparator =
                    new Comparator<K>() {
                        public int compare(K k1, K k2) {
                            int compare =
                                    map.get(k1).compareTo(map.get(k2));
                            if (compare == 0)
                                return 1;
                            else
                                return compare;
                        }
                    };

            Map<K, V> sortedByValues =
                    new TreeMap<K, V>(valueComparator);
            sortedByValues.putAll(map);
            return sortedByValues;
        }
		String auto_decode(String str) {
			int repeats = 20;
			int repeat = 0;
			boolean matched;
			String test;
			String tag = "";
			do {
			    String startStr = str;
				matched = false;
				if(Pattern.compile("^\\x1f\\x8b\\x08").matcher(str).find()) {
                    str = this.gzip_decompress(str);
                    matched = true;
                    tag = "gzip";
                }
				if(Pattern.compile("[01]{4,}\\s+[01]{4,}").matcher(str).find()) {
					str = this.bin2ascii(str);
					matched = true;
					tag = "binary";
				}
                if(Pattern.compile("(?:[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                    test = this.hex2ascii(str);
                    if(Pattern.compile("^[\\x09-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                        str = test;
                        tag = "hex";
                        repeat++;
                        continue;
                    }
                }
				if(!Pattern.compile("[^\\d,\\s]").matcher(str).find() && Pattern.compile("\\d+[,\\s]+").matcher(str).find()) {
					str = this.from_charcode(str);
					matched = true;
                    tag = "charcode";
				}
                if(Pattern.compile("(?:\\\\[0]{0,4}[0-9a-fA-F]{2}[\\s,\\-]?){3,}").matcher(str).find()) {
                    test = this.decode_css_escapes(str);
                    if(Pattern.compile("^[\\x09-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                        str = test;
                        matched = true;
                        tag = "css_escapes";
                    }
                }
				if(Pattern.compile("\\\\x[0-9a-f]{2}",Pattern.CASE_INSENSITIVE).matcher(str).find() || Pattern.compile("\\\\[0-9]{1,3}").matcher(str).find() || Pattern.compile("\\\\u[0-9a-f]{4}",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
				    test = this.decode_js_string(str);
                    if(Pattern.compile("^[\\x09-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                        str = test;
                        matched = true;
                        tag = "jsstring";
                    }
				}
				if(Pattern.compile("&[a-zA-Z]+;",Pattern.CASE_INSENSITIVE).matcher(str).find() || Pattern.compile("&#x?[0-9a-f]+;?",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
					str = this.decode_html5_entities(str);
					matched = true;
                    tag = "htmlentities";
				}
				if(Pattern.compile("%[0-9a-f]{2}",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
					str = this.decode_url(str);
					matched = true;
                    tag = "urldecode";
				}
                if(Pattern.compile("^[a-zA-Z0-9\\-_.]+$",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
                    String[] parts = str.split("\\.");
                    if(parts.length == 3 && !d_jwt_get_header(str).equals("Invalid token")) {
                        return d_jwt_get_header(str) + "\n" +d_jwt_get_payload(str) + "\n" + decode_base64url(parts[2]);
                    }
                }
				if(Pattern.compile("[a-zA-Z0-9+/]{4,}=*$",Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0) {
					test = this.decode_base64(str);
					if(Pattern.compile("^[\\x00-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
						str = test;
						matched = true;
                        tag = "base64";
					}
				}

                if(Pattern.compile("[A-Z0-9+/]{4,}=*$",Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0) {
				    test = this.decode_base32(str);
				    if(Pattern.compile("^[\\x00-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
                        str = test;
                        matched = true;
                        tag = "base32";
                    }
                }
                if(Pattern.compile("(?:[a-zA-Z]+[\\s,-]){2,}").matcher(str).find()) {
                    double total = 0;
                    double bestScore = -9999999;
                    int n = 0;
				    for(int i = 1; i <= 25;i++) {
				        String rotString = rotN(str, i);
				        double score = is_like_english(rotString);
                        total += score;
                        if(score > bestScore) {
                            bestScore = score;
                            n = i;
                        }
                    }
                    double average = (total / 25);
                    if((((average - bestScore) / average) * 100) > 40) {
                        str = rotN(str, n);
                        matched = true;
                        tag = "rotN";
                    }
                }

                if(Pattern.compile("(?:[a-z]+[\\s,-]){2,}").matcher(str).find()) {
                    double total = 0;
                    double bestScore = -9999999;
                    int key1 = 0;
                    int key2 = 0;
                    int[] keyArray1 = {1,3,5,7,9,11,15,17,19,21,23,25};
                    int[] keyArray2 = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25};
                    for(int i = 0; i < keyArray1.length;i++) {
                        for(int j = 0; j < keyArray2.length;j++) {
                            String decodedString = affine_decrypt(str, keyArray1[i], keyArray2[j]);
                            double score = is_like_english(decodedString);
                            total += score;
                            if (score > bestScore) {
                                bestScore = score;
                                key1 = keyArray1[i];
                                key2 = keyArray2[j];
                            }
                        }
                    }
                    double average = (total / 25);
                    if((((average - bestScore) / average) * 100) > 40) {
                        str = affine_decrypt(str, key1, key2);
                        matched = true;
                        tag = "affine";
                    }
                }

                if(Pattern.compile("(?:[a-z]+[\\s,-]){2,}").matcher(str).find()) {
				    String plaintext = atbash_decrypt(str);
				    if(is_like_english(plaintext) - is_like_english(str) >= 200) {
				        str = plaintext;
				        matched = true;
				        tag = "atbash";
                    }
                }
                if(Pattern.compile("^[a-z]{10,}$").matcher(str).find()) {
				    double total = 0;
                    double bestScore = -9999999;
                    int n = 0;
                    double max = Math.floor(2 * str.length() - 1);
				    for (int i = 2; i < max; i++) {
                        String decodedString = rail_fence_decrypt(str, i);
                        double score = is_like_english(decodedString);
                        total += score;
                        if(score > bestScore) {
                            bestScore = score;
                            n = i;
                        }
                    }
                    double average = (total / max-1);
                    if((((average - bestScore) / average) * 100) > 40) {
                        str = rail_fence_decrypt(str, n);
                        matched = true;
                        tag = "rail_fence";
                    }
                }

                if(Pattern.compile("^[\\x00-\\xff]+$",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
				    int lenGuess = guess_key_length(str);
                    test = xor_decrypt(str, lenGuess, false);
                    int alphaCount = test.replaceAll("[^a-zA-Z0-9]+","").length();
                    int strLen = str.length();
                    float percent = (((float) alphaCount/strLen)*100);
                    if(is_like_english(test) < is_like_english(str) && percent > 60) {
                        str = test;
                        matched = true;
                        tag = "xor";
                    }
                }
				if(!matched || startStr.equals(str)) {
					break;
				}
                //System.out.println("Pass:"+repeat+"; value="+str+"; tag="+tag);
				repeat++;
			} while(repeat < repeats);
			return str;
		}
		String range(String str, int from, int to, int step) {
			ArrayList<Integer> output = new ArrayList<Integer>();
			to++;
			if(from >= 0 && to-from<=10000 && step > 0) {
				for(int i=from;i<to;i+=step) {
					output.add(i);
				}
			}
			return StringUtils.join(output,",");
		}
		String total(String str) {
			String[] chars = str.split(",");
			int total = 0;
			for(int i=0;i<chars.length;i++) {
				try {
					total += Integer.parseInt(chars[i]);
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}
			}
			return Integer.toString(total);
		}
		String arithmetic(String str, int amount, String operation, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			ArrayList<String> output = new ArrayList<>();
			int num = 0;
			for(int i=0;i<chars.length;i++) {
			   try {
				   num = Integer.parseInt(chars[i]);
                   switch (operation) {
                       case "+":
                           num = num + amount;
                           break;
                       case "-":
                           num = num - amount;
                           break;
                       case "/":
                           num = num / amount;
                           break;
                       case "*":
                           num = num * amount;
                           break;
                       case "%":
                           num = num % amount;
                           break;
                       case ">>":
                           num = num >> amount;
                           break;
                       case ">>>":
                           num = num >>> amount;
                           break;
                       case "<<":
                           num = num << amount;
                           break;
                   }
				   output.add(""+num);
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
		   }
		   return StringUtils.join(output, ",");
		}
		String convert_base(String str, String splitChar, int from, int to) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			for(int i=0;i<chars.length;i++) {
				try {
					chars[i] = ""+Integer.toString(Integer.parseInt(chars[i], from), to);
				} catch(NumberFormatException e){
					stderr.println(e.getMessage());
				}				
			}
			return StringUtils.join(chars, ",");
		}
		String zeropad(String str, String splitChar, int amount) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			if(amount > 0 && amount < 10000) {
				for(int i=0;i<chars.length;i++) {
					chars[i] = StringUtils.leftPad(chars[i], amount, '0');
				}
			}
			return StringUtils.join(chars, ",");
		}
		String eval_fromcharcode(String str) {
			return "eval(String.fromCharCode("+this.to_charcode(str)+"))";
		}
		String behavior(String str) {
			return "<PUBLIC:ATTACH EVENT=onload ONEVENT="+str+" FOR=window />";
		}
		String css_expression(String str) {
			return "xss:expression(open("+str+"))";
		}
		String datasrc(String str) {
			return "<xml ID=xss><x><B>&lt;IMG src=1 onerror="+str+"&gt;</B></x></xml><SPAN DATASRC=#xss DATAFLD=B DATAFORMATAS=HTML></SPAN>";
		}
		String iframe_data_url(String str) {
			return "<iframe src=data:text/html;base64,"+this.base64Encode(str)+">";
		}
		String uppercase_script(String str) {
			return "<SVG><SCRIPT>"+this.dec_entities(str)+"</SCRIPT></SVG>";
		}
		String script_data(String str) {
			return "<script src=data:;base64,"+this.base64Encode(str)+"></script>";
		}
		String throw_eval(String str) {
            String out = "window.onerror=eval;throw'=";
            for(int i=0;i<str.length();i++) {
                char chr = str.charAt(i);
                if(Character.isDigit(chr) || Character.isAlphabetic(chr)) {
                    out += chr;
                } else {
                    out += this.hex_escapes(""+chr);
                }
            }
            out += "'";
            return out;
        }
		String iframe_src_doc(String str) {
			return "<iframe srcdoc="+this.html5_entities(str)+"></iframe>";
		}
		String template_eval(String str) {
			return "eval(`"+str.replaceAll("(.)","$1\\${[]}")+"`)";
		}
		private String callTag(String tag, String output, ArrayList<String> arguments) {
            switch (tag) {
                case "utf16":
                    output = this.utf16(output);
                    break;
                case "utf16be":
                    output = this.utf16be(output);
                    break;
                case "utf16le":
                    output = this.utf16le(output);
                    break;
                case "utf32":
                    output = this.utf32(output);
                    break;
                case "shift_jis":
                    output = this.shift_jis(output);
                    break;
                case "gb2312":
                    output = this.gb2312(output);
                    break;
                case "euc_kr":
                    output = this.euc_kr(output);
                    break;
                case "euc_jp":
                    output = this.euc_jp(output);
                    break;
                case "gbk":
                    output = this.gbk(output);
                    break;
                case "big5":
                    output = this.big5(output);
                    break;
                case "charset_convert":
                    output = this.charset_convert(output, this.getString(arguments, 0), this.getString(arguments, 1));
                    break;
                case "gzip_compress":
                    output = this.gzip_compress(output);
                    break;
                case "gzip_decompress":
                    output = this.gzip_decompress(output);
                    break;
                case "bzip2_compress":
                    output = this.bzip2_compress(output);
                    break;
                case "bzip2_decompress":
                    output = this.bzip2_decompress(output);
                    break;
                case "deflate_compress":
                    output = this.deflate_compress(output);
                    break;
                case "deflate_decompress":
                    output = this.deflate_decompress(output);
                    break;
                case "html_entities":
                    output = this.html_entities(output);
                    break;
                case "d_html_entities":
                    output = this.decode_html_entities(output);
                    break;
                case "html5_entities":
                    output = this.html5_entities(output);
                    break;
                case "hex":
                    output = this.hex(output, this.getString(arguments, 0));
                    break;
                case "hex_entities":
                    output = this.hex_entities(output);
                    break;
                case "hex_escapes":
                    output = this.hex_escapes(output);
                    break;
                case "octal_escapes":
                    output = this.octal_escapes(output);
                    break;
                case "php_non_alpha":
                    output = this.php_non_alpha(output);
                    break;
                case "php_chr":
                    output = this.php_chr(output);
                    break;
                case "sql_hex":
                    output = this.sql_hex(output);
                    break;
                case "rotN":
                    output = this.rotN(output, this.getInt(arguments, 0));
                    break;
                case "rotN_bruteforce":
                    output = this.rotN_bruteforce(output);
                    break;
                case "xor":
                    output = this.xor(output, this.getString(arguments, 0));
                    break;
                case "xor_decrypt":
                    output = this.xor_decrypt(output, this.getInt(arguments, 0), false);
                    break;
                case "xor_getkey":
                    output = this.xor_getkey(output);
                    break;
                case "affine_encrypt":
                    output = this.affine_encrypt(output, this.getInt(arguments, 0), this.getInt(arguments, 1));
                    break;
                case "affine_decrypt":
                    output = this.affine_decrypt(output, this.getInt(arguments, 0), this.getInt(arguments, 1));
                    break;
                case "atbash_encrypt":
                    output = this.atbash_encrypt(output);
                    break;
                case "atbash_decrypt":
                    output = this.atbash_decrypt(output);
                    break;
                case "rail_fence_encrypt":
                    output = this.rail_fence_encrypt(output, this.getInt(arguments, 0));
                    break;
                case "rail_fence_decrypt":
                    output = this.rail_fence_decrypt(output, this.getInt(arguments, 0));
                    break;
                case "substitution_encrypt":
                    output = this.substitution_encrypt(output, this.getString(arguments, 0));
                    break;
                case "substitution_decrypt":
                    output = this.substitution_decrypt(output, this.getString(arguments, 0));
                    break;
                case "jwt":
                    output = this.jwt(output, this.getString(arguments, 0), this.getString(arguments, 1));
                    break;
                case "auto_decode":
                    output = this.auto_decode(output);
                    break;
                case "d_octal_escapes":
                    output = this.decode_octal_escapes(output);
                    break;
                case "css_escapes":
                    output = this.css_escapes(output);
                    break;
                case "css_escapes6":
                    output = this.css_escapes6(output);
                    break;
                case "dec_entities":
                    output = this.dec_entities(output);
                    break;
                case "unicode_escapes":
                    output = this.unicode_escapes(output);
                    break;
                case "d_unicode_escapes":
                    output = this.decode_js_string(output);
                    break;
                case "d_jwt_get_payload":
                    output = this.d_jwt_get_payload(output);
                    break;
                case "d_jwt_get_header":
                    output = this.d_jwt_get_header(output);
                    break;
                case "d_jwt_verify":
                    output = this.d_jwt_verify(output, this.getString(arguments, 0));
                    break;
                case "d_js_string":
                    output = this.decode_js_string(output);
                    break;
                case "d_html5_entities":
                    output = this.decode_html5_entities(output);
                    break;
                case "base32":
                    output = this.base32_encode(output);
                    break;
                case "d_base32":
                    output = this.decode_base32(output);
                    break;
                case "base64":
                    output = this.base64Encode(output);
                    break;
                case "d_base64":
                    output = this.decode_base64(output);
                    break;
                case "base64url":
                    output = this.base64urlEncode(output);
                    break;
                case "d_base64url":
                    output = this.decode_base64url(output);
                    break;
                case "urlencode":
                    output = this.urlencode(output);
                    break;
                case "urlencode_not_plus":
                    output = this.urlencode_not_plus(output);
                    break;
                case "urlencode_all":
                    output = this.urlencode_all(output);
                    break;
                case "d_url":
                    output = this.decode_url(output);
                    break;
                case "d_css_escapes":
                    output = this.decode_css_escapes(output);
                    break;
                case "uppercase":
                    output = this.uppercase(output);
                    break;
                case "lowercase":
                    output = this.lowercase(output);
                    break;
                case "capitalise":
                    output = this.capitalise(output);
                    break;
                case "uncapitalise":
                    output = this.uncapitalise(output);
                    break;
                case "from_charcode":
                    output = this.from_charcode(output);
                    break;
                case "to_charcode":
                    output = this.to_charcode(output);
                    break;
                case "reverse":
                    output = this.reverse(output);
                    break;
                case "length":
                    output = this.len(output);
                    break;
                case "find":
                    output = this.find(output, this.getString(arguments, 0));
                    break;
                case "replace":
                    output = this.replace(output, this.getString(arguments, 0), this.getString(arguments, 1));
                    break;
                case "regex_replace":
                    output = this.regex_replace(output, this.getString(arguments, 0), this.getString(arguments, 1));
                    break;
                case "repeat":
                    output = this.repeat(output, this.getInt(arguments, 0));
                    break;
                case "split_join":
                    output = this.split_join(output, this.getString(arguments, 0), this.getString(arguments, 1));
                    break;
                case "is_like_english":
                    output = Double.toString(this.is_like_english(output));
                    break;
                case "index_of_coincidence":
                    output = Double.toString(this.index_of_coincidence(output));
                    break;
                case "guess_key_length":
                    output = Integer.toString(this.guess_key_length(output));
                    break;
                case "dec2hex":
                    output = this.dec2hex(output, this.getString(arguments, 0));
                    break;
                case "dec2oct":
                    output = this.dec2oct(output, this.getString(arguments, 0));
                    break;
                case "dec2bin":
                    output = this.dec2bin(output, this.getString(arguments, 0));
                    break;
                case "hex2dec":
                    output = this.hex2dec(output, this.getString(arguments, 0));
                    break;
                case "oct2dec":
                    output = this.oct2dec(output, this.getString(arguments, 0));
                    break;
                case "bin2dec":
                    output = this.bin2dec(output, this.getString(arguments, 0));
                    break;
                case "ascii2bin":
                    output = this.ascii2bin(output);
                    break;
                case "bin2ascii":
                    output = this.bin2ascii(output);
                    break;
                case "hex2ascii":
                    output = this.hex2ascii(output);
                    break;
                case "ascii2hex":
                    output = this.ascii2hex(output, this.getString(arguments, 0));
                    break;
                case "ascii2reverse_hex":
                    output = this.ascii2reverse_hex(output, this.getString(arguments, 0));
                    break;
                case "sha1":
                    output = this.sha1(output);
                    break;
                case "sha224":
                    output = this.sha224(output);
                    break;
                case "sha256":
                    output = this.sha256(output);
                    break;
                case "sha384":
                    output = this.sha384(output);
                    break;
                case "sha512":
                    output = this.sha512(output);
                    break;
                case "sha3":
                    output = this.sha3(output);
                    break;
                case "sha3_224":
                    output = this.sha3_224(output);
                    break;
                case "sha3_256":
                    output = this.sha3_256(output);
                    break;
                case "sha3_384":
                    output = this.sha3_384(output);
                    break;
                case "sha3_512":
                    output = this.sha3_512(output);
                    break;
                case "skein_256_128":
                    output = this.skein_256_128(output);
                    break;
                case "skein_256_160":
                    output = this.skein_256_160(output);
                    break;
                case "skein_256_224":
                    output = this.skein_256_224(output);
                    break;
                case "skein_256_256":
                    output = this.skein_256_256(output);
                    break;
                case "skein_512_128":
                    output = this.skein_512_128(output);
                    break;
                case "skein_512_160":
                    output = this.skein_512_160(output);
                    break;
                case "skein_512_224":
                    output = this.skein_512_224(output);
                    break;
                case "skein_512_256":
                    output = this.skein_512_256(output);
                    break;
                case "skein_512_384":
                    output = this.skein_512_384(output);
                    break;
                case "skein_512_512":
                    output = this.skein_512_512(output);
                    break;
                case "skein_1024_384":
                    output = this.skein_1024_384(output);
                    break;
                case "skein_1024_512":
                    output = this.skein_1024_512(output);
                    break;
                case "skein_1024_1024":
                    output = this.skein_1024_1024(output);
                    break;
                case "sm3":
                    output = this.sm3(output);
                    break;
                case "tiger":
                    output = this.tiger(output);
                    break;
                case "md2":
                    output = this.md2(output);
                    break;
                case "md4":
                    output = this.md4(output);
                    break;
                case "md5":
                    output = this.md5(output);
                    break;
                case "gost3411":
                    output = this.gost3411(output);
                    break;
                case "ripemd128":
                    output = this.ripemd128(output);
                    break;
                case "ripemd160":
                    output = this.ripemd160(output);
                    break;
                case "ripemd256":
                    output = this.ripemd256(output);
                    break;
                case "ripemd320":
                    output = this.ripemd320(output);
                    break;
                case "whirlpool":
                    output = this.whirlpool(output);
                    break;
                case "random":
                    output = this.random(output, this.getInt(arguments, 0));
                    break;
                case "random_unicode":
                    output = this.random_unicode(this.getInt(arguments, 0), this.getInt(arguments, 1), this.getInt(arguments, 2));
                    break;
                case "range":
                    output = this.range(output, this.getInt(arguments, 0), this.getInt(arguments, 1), this.getInt(arguments, 2));
                    break;
                case "total":
                    output = this.total(output);
                    break;
                case "arithmetic":
                    output = this.arithmetic(output, this.getInt(arguments, 0), this.getString(arguments, 1), this.getString(arguments, 2));
                    break;
                case "convert_base":
                    output = this.convert_base(output, this.getString(arguments, 0), this.getInt(arguments, 1), this.getInt(arguments, 2));
                    break;
                case "zeropad":
                    output = this.zeropad(output, this.getString(arguments, 0), this.getInt(arguments, 1));
                    break;
                case "behavior":
                    output = this.behavior(output);
                    break;
                case "css_expression":
                    output = this.css_expression(output);
                    break;
                case "datasrc":
                    output = this.datasrc(output);
                    break;
                case "eval_fromcharcode":
                    output = this.eval_fromcharcode(output);
                    break;
                case "iframe_data_url":
                    output = this.iframe_data_url(output);
                    break;
                case "script_data":
                    output = this.script_data(output);
                    break;
                case "uppercase_script":
                    output = this.uppercase_script(output);
                    break;
                case "iframe_src_doc":
                    output = this.iframe_src_doc(output);
                    break;
                case "template_eval":
                    output = this.template_eval(output);
                    break;
                case "throw_eval":
                    output = this.throw_eval(output);
                    break;
            }
			return output;
		}
		void clearTags() {
			String input = inputArea.getText();	                	
			input = input.replaceAll("<@/?\\w+_\\d+(?:[(](?:,?"+argumentsRegex+")*[)])?(?:\\s@/)?>","");
      	  	inputArea.setText(input);	                	  	                	  
      	  	inputArea.requestFocus();
		}
		String convertNoInputTags(String input) {
            List<String> allMatches = new ArrayList<>();
            Matcher m = Pattern.compile("<@([\\w\\d]+_\\d+)((?:[(](?:,?"+argumentsRegex+")*[)])?) @/>").matcher(input);
            while (m.find()) {
                allMatches.add(m.group(1));
            }
            for(String tagNameWithID:allMatches) {
                String arguments = "";
                String tagName = tagNameWithID.replaceAll("_\\d+$","");
                m = Pattern.compile("<@"+tagNameWithID+"((?:[(](?:,?"+argumentsRegex+")*[)])?) @/>").matcher(input);
                if(m.find()) {
                    arguments = m.group(1);
                }
                String result = this.callTag(tagName,"", this.parseArguments(arguments));
                input = input.replaceAll("<@"+tagNameWithID+"(?:[(](?:,?"+argumentsRegex+")*[)])? @/>", result.replace("\\","\\\\").replace("$","\\$"));
            }
            return input;
        }
		String convert(String input) {
            if(input.contains(" @/>")) {
                input = convertNoInputTags(input);
            }
			String output = input;
			List<String> allMatches = new ArrayList<>();
			 Matcher m = Pattern.compile("<@/([\\w\\d]+_\\d+)>").matcher(input);			 
			 while (m.find()) {
			   allMatches.add(m.group(1));
			 }
			 for(String tagNameWithID:allMatches) {
				 String code = "";
				 String arguments = "";
				 String tagName = tagNameWithID.replaceAll("_\\d+$","");				 
				 m = Pattern.compile("<@"+tagNameWithID+"((?:[(](?:,?"+argumentsRegex+")*[)])?)>([\\d\\D]*?)<@/"+tagNameWithID+">").matcher(output);
				 if(m.find()) {
					arguments = m.group(1);
					code = m.group(2); 
				 } 	
				 String result = this.callTag(tagName,code,this.parseArguments(arguments));
				 output = output.replaceAll("<@"+tagNameWithID+"(?:[(](?:,?"+argumentsRegex+")*[)])?>[\\d\\D]*?<@/"+tagNameWithID+">", result.replace("\\","\\\\").replace("$","\\$"));
			 }
			return output;			
		}
		void setInput(String input) {
			inputArea.setText(input);
		}
		int calculateRealLen(String str) {
			int len = 0;
			for(int i=0;i<str.length();i++) {
				int cp = Character.codePointAt(str, i);
				if(cp <= 0x007F) {
					len++;
				} else if(cp <= 0x07FF) {
					len+=2;
				} else if(cp <= 0xFFFF) {
					len+=3;
				} else if(cp <= 0x10FFFF) {
					len+=4;
				}		
			}
			return len;
		}
		private String getString(ArrayList<String> args,Integer pos) {
			if(args.size() < pos+1) {
				return "";
			}
			return args.get(pos);
		}
		private Integer getInt(ArrayList<String> args,Integer pos) {
            Integer output;
            output = 0;
            if(args.size() < pos+1) {
				return 0;
			}
			if(args.get(pos).contains("0x")) {
                try {
                    return Integer.parseInt(args.get(pos).replaceAll("^0x",""),16);
                } catch(NumberFormatException e){
                    stderr.println(e.getMessage());
                }
            }
			try {
				output = Integer.parseInt(args.get(pos));
			} catch(NumberFormatException e){
				stderr.println(e.getMessage());
			}
			return output;
		}
		private ArrayList<String> parseArguments(String arguments) {
			if(arguments.length() == 0) {
				return new ArrayList<>();
			}
			arguments = arguments.substring(1, arguments.length()-1);
			String argument1;
			String argument2;
			String argument3;
			ArrayList<String> convertedArgs = new ArrayList<>();
			String regex = "("+argumentsRegex+")(,"+argumentsRegex+")?(,"+argumentsRegex+")?";			
			Matcher m = Pattern.compile(regex).matcher(arguments);
			 if(m.find()) {
				argument1 = m.group(1);
				argument2 = m.group(2);
				argument3 = m.group(3);
				if(argument1 != null) {
					String chr = ""+argument1.charAt(0); 
					if(chr.equals("'") || chr.equals("\"")) {
						argument1 = argument1.substring(1, argument1.length()-1);
						argument1 = argument1.replace("\\'", "'").replace("\\\"", "\"");						
						convertedArgs.add(this.decode_js_string(argument1));
					} else {
						convertedArgs.add(argument1);
					}
				}
				if(argument2 != null) {
					argument2 = argument2.substring(1);
					String chr = ""+argument2.charAt(0); 
					if(chr.equals("'") || chr.equals("\"")) {
						argument2 = argument2.substring(1, argument2.length()-1);
						argument2 = argument2.replace("\\'", "'").replace("\\\"", "\"");
						convertedArgs.add(this.decode_js_string(argument2));
					} else {
						convertedArgs.add(argument2);
					}
				}
				if(argument3 != null) {
					argument3 = argument3.substring(1);
					String chr = ""+argument3.charAt(0); 
					if(chr.equals("'") || chr.equals("\"")) {
						argument3 = argument3.substring(1, argument3.length()-1);
						argument3 = argument3.replace("\\'", "'").replace("\\\"", "\"");
						convertedArgs.add(this.decode_js_string(argument3));
					} else {
						convertedArgs.add(argument3);
					}
				}
			 } 
			return convertedArgs;
		}
		private JScrollPane createButtonsOrMenu(String category, final String type, JMenu parentMenu, final IContextMenuInvocation invocation) {
			JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
			JScrollPane scrollFrame = new JScrollPane(panel,JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			tags.sort((t1, t2) -> t1.name.compareToIgnoreCase(t2.name));
			
			for(final Tag tagObj:tags) {
                final JButton btn = new JButton(tagObj.name);
                btn.setToolTipText(tagObj.tooltip);
                final JMenuItem menu = new JMenuItem(tagObj.name);
                menu.setToolTipText(tagObj.tooltip);

				ActionListener actionListener;
				if(category.equals(tagObj.category)) {
					if(type.equals("button")) {
                        btn.setBackground(Color.decode("#005a70"));
                        btn.setForeground(Color.white);
                        btn.putClientProperty("tag", tagObj);
                    }

                    actionListener = e -> {
                        String selectedText = null;
                        if(type.equals("button")) {
                            selectedText = inputArea.getSelectedText();
                            if (selectedText == null) {
                                selectedText = "";
                            }
                        }
                        String tagStart = "<@"+tagObj.name+"_"+tagCounter;
                        if(tagObj.argument1 != null) {
                            tagStart += "(";
                        }
                        if(tagObj.argument1 != null) {
                            if(tagObj.argument1.type.equals("int")) {
                                tagStart += tagObj.argument1.value;
                            } else if(tagObj.argument1.type.equals("string")) {
                                tagStart += "\"" + tagObj.argument1.value + "\"";
                            }
                        }
                        if(tagObj.argument2 != null) {
                            tagStart += ",";
                            if(tagObj.argument2.type.equals("int")) {
                                tagStart += tagObj.argument2.value;
                            } else if(tagObj.argument2.type.equals("string")) {
                                tagStart += "\"" + tagObj.argument2.value + "\"";
                            }
                        }
                        if(tagObj.argument3 != null) {
                            tagStart += ",";
                            if(tagObj.argument3.type.equals("int")) {
                                tagStart += tagObj.argument3.value;
                            } else if(tagObj.argument3.type.equals("string")) {
                                tagStart += "\"" + tagObj.argument3.value + "\"";
                            }
                        }
                        if(tagObj.argument1 != null) {
                            tagStart += ")";
                        }
                        String tagEnd;
                        if(tagObj.hasInput) {
                            tagStart += ">";
                            tagEnd = "<@/" + tagObj.name + "_" + tagCounter + ">";
                        } else {
                            tagStart += " @/>";
                            tagEnd = "";
                        }
                        if(type.equals("button")) {
                            inputArea.replaceSelection(tagStart + selectedText + tagEnd);
                        } else {
                            if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                                int[] bounds = invocation.getSelectionBounds();
                                byte[] message = invocation.getSelectedMessages()[0].getRequest();
                                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                                try {
                                    outputStream.write(Arrays.copyOfRange(message, 0, bounds[0]));
                                    outputStream.write(helpers.stringToBytes(tagStart));
                                    outputStream.write(Arrays.copyOfRange(message,bounds[0], bounds[1]));
                                    outputStream.write(helpers.stringToBytes(tagEnd));
                                    outputStream.write(Arrays.copyOfRange(message, bounds[1],message.length));
                                    outputStream.flush();
                                    invocation.getSelectedMessages()[0].setRequest(outputStream.toByteArray());
                                } catch (IOException e1) {
                                    System.err.println(e1.toString());
                                }
                            }
                        }
                        tagCounter++;
                        if(type.equals("button")) {
                            outputArea.setText(hv.convert(inputArea.getText()));
                            outputArea.selectAll();
                        }
                    };

                    if(type.equals("button")) {
                        btn.addActionListener(actionListener);
                        panel.add(btn);
                    } else {
                        menu.addActionListener(actionListener);
                        parentMenu.add(menu);
                    }
				}
			}
			return scrollFrame;
		}
	}

}
