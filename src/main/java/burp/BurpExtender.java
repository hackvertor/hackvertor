package burp;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.Document;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.unbescape.css.CssEscape;
import org.unbescape.css.CssStringEscapeLevel;
import org.unbescape.css.CssStringEscapeType;
import org.unbescape.html.HtmlEscape;
import org.unbescape.html.HtmlEscapeLevel;
import org.unbescape.html.HtmlEscapeType;
import org.unbescape.javascript.JavaScriptEscape;
import org.unbescape.javascript.JavaScriptEscapeLevel;
import org.unbescape.javascript.JavaScriptEscapeType;

import java.lang.reflect.Method;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JTabbedPaneClosable inputTabs;
	private int tabCounter = 1;
	private PrintWriter stderr;
	PrintWriter stdout;
	private Hackvertor hv;
	private Hackvertor hvInRequest;
	public GridBagConstraints createConstraints(int x, int y, int gridWidth) {
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 0.5; 
        c.weighty = 0;
        c.gridx = x;
        c.gridy = y;
        c.ipadx = 0;
        c.ipady = 0;
        c.gridwidth = gridWidth;            
		return c;
	}
	protected ImageIcon createImageIcon(String path, String description) {
		java.net.URL imgURL = getClass().getResource(path);
        if (imgURL != null) {
			return new ImageIcon(imgURL, description);
		} else {
			stderr.println("Couldn't find file: " + path);
			return null;
		}
	}
	public boolean hasMethodAnd1Arg(Object obj, String methodStr) {
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
	public JPanel generateBlankPanel() {
        JPanel blankPanel = new JPanel();
        blankPanel.setMaximumSize(new Dimension(0,0));
        blankPanel.setVisible(false);
        return blankPanel;
    }
    public Hackvertor generateHackvertor() {
        JTabbedPane tabs = new JTabbedPane();
        hv = new Hackvertor();
        hv.init();
        hv.buildTabs(tabs);
        JPanel topBar = new JPanel(new GridBagLayout());
        JLabel logoLabel = new JLabel(createImageIcon("/images/logo.gif","logo"));
        final JTextArea hexView = new JTextArea(20,10);
        hexView.setOpaque(true);
        hexView.setEditable(false);
        hexView.setLineWrap(true);
        hexView.setBackground(Color.decode("#FFF5BF"));
        hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
        hexView.setVisible(false);
        final JScrollPane hexScroll = new JScrollPane(hexView);
        hexScroll.setMinimumSize(new Dimension(500,100));
        JPanel buttonsPanel = new JPanel(new GridBagLayout());
        JPanel panel = new JPanel(new GridBagLayout());
        hv.setPanel(panel);
        final JTextArea inputArea = new JTextArea(20,10);
        hv.setInputArea(inputArea);
        inputArea.setLineWrap(true);
        inputArea.setMinimumSize(new Dimension(300,300));
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
        inputScroll.setMinimumSize(new Dimension(300,300));
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
        final JTextArea outputArea = new JTextArea(20,10);
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
        outputArea.setMinimumSize(new Dimension(300,300));
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
        outputScroll.setMinimumSize(new Dimension(300,300));
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
        buttonsPanel.add(clearButton,createConstraints(0,0,1));
        buttonsPanel.add(clearTagsButton,createConstraints(1,0,1));
        buttonsPanel.add(swapButton,createConstraints(2,0,1));
        buttonsPanel.add(selectInputButton,createConstraints(3,0,1));
        buttonsPanel.add(selectOutputButton,createConstraints(4,0,1));
        buttonsPanel.add(pasteInsideButton,createConstraints(5,0,1));
        buttonsPanel.add(convertButton,createConstraints(6,0,1));
        GridBagConstraints c = createConstraints(4,1,1);
        c.anchor = GridBagConstraints.EAST;
        c.fill = GridBagConstraints.BOTH;
        c.ipadx = 20;
        c.ipady = 20;
        c.weightx = 0;
        topBar.add(logoLabel,c);
        topBar.add(tabs,createConstraints(0,1,3));
        c = createConstraints(0,0,5);
        panel.add(topBar,c);
        JPanel inputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = createConstraints(0,0,1);
        c.insets = new Insets(5,5,5,5);
        c.weightx = 0;
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLabel,c);
        c = createConstraints(1,1,1);
        c.insets = new Insets(5,5,5,5);
        c.weightx = 0;
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputLenLabel,c);
        c = createConstraints(2,1,1);
        c.insets = new Insets(5,5,5,5);
        c.weightx = 0;
        c.anchor = GridBagConstraints.WEST;
        inputLabelsPanel.add(inputRealLenLabel,c);
        panel.add(inputLabelsPanel,createConstraints(0,2,1));
        panel.add(inputScroll,createConstraints(0,3,1));
        JPanel outputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        c = createConstraints(0,1,1);
        c.insets = new Insets(5,5,5,5);
        c.weightx = 0;
        outputLabelsPanel.add(outputLabel,c);
        c = createConstraints(1,1,1);
        c.insets = new Insets(5,5,5,5);
        c.weightx = 0;
        outputLabelsPanel.add(outputLenLabel,c);
        c = createConstraints(2,1,1);
        c.insets = new Insets(5,5,5,5);
        c.weightx = 0;
        outputLabelsPanel.add(outputRealLenLabel,c);
        panel.add(outputLabelsPanel,createConstraints(1,2,1));
        panel.add(outputScroll,createConstraints(1,3,1));
        c = createConstraints(0,4,5);
        panel.add(buttonsPanel,c);
        c = createConstraints(0,5,5);
        c.insets = new Insets(5,5,5,5);
        panel.add(hexScroll,c);
        c = createConstraints(0,6,1);
        c.weighty = 1;
        panel.add(new JPanel(),c);
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
		this.callbacks = callbacks;
		callbacks.setExtensionName("Hackvertor");
		callbacks.registerContextMenuFactory(this);
		callbacks.registerHttpListener(this);
		 SwingUtilities.invokeLater(new Runnable() 
	        {
	            public void run()
	            {	   
	            	stdout.println("Hackvertor v0.6.6");
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
	            }
	        });
		
	}

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(!messageIsRequest) {
            return;
        }
        byte[] request = messageInfo.getRequest();
	    if(helpers.indexOf(request,helpers.stringToBytes("<@/"), true, 0, request.length) != -1) {
            Hackvertor hv = new Hackvertor();
            messageInfo.setRequest(helpers.stringToBytes(hv.convert(helpers.bytesToString(request))));
        }
    }

	public String getTabCaption() {
		return "Hackvertor";
	}
	
	public int getTabIndex(ITab your_itab) {
		JTabbedPane parent = (JTabbedPane) your_itab.getUiComponent().getParent();
		for(int i = 0; i < parent.getTabCount(); ++i) {
			if(your_itab.getTabCaption().equals(parent.getTitleAt(i))) {
				return i;
			}
		}
		return -1;
	}

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		int[] bounds = invocation.getSelectionBounds();
		
		switch (invocation.getInvocationContext()) {
			case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
			case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
			case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
			break;
			default:
				return null;
		}
		
		if(bounds[0] == bounds[1]) {
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
        
        public HackvertorAction(String text, IContextMenuInvocation invocation) {
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
		public String name;
		public String tag;
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
		public String category;
		public String name;
		public TagArgument argument1 = null;
		public TagArgument argument2 = null;
		public TagArgument argument3 = null;
		Tag(String tagCategory, String tagName) {
			this.category = tagCategory;
			this.name = tagName;
			if(hasMethodAnd1Arg(hv,tagName)) {
				callbacks.registerIntruderPayloadProcessor(new HackvertorPayloadProcessor("Hackvertor_"+hv.capitalise(tagName),tagName));
			}
		}
	}
	class TagArgument {
		public String type;
		public String value;
		TagArgument(String type, String value) {
			this.type = type;
			this.value = value;
		}
	}
	class Hackvertor {	
		private int tagCounter = 0;
		public String argumentsRegex = "(?:\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")";
		private ArrayList<Tag> tags = new ArrayList<Tag>();
		private JTextArea inputArea;
        private JTextArea outputArea;
        private JPanel panel;
        private String[] categories = {
                "Charsets","Encode","Decode","Convert","String","Hash","Math","XSS"
        };
        public void setInputArea(JTextArea inputArea) {
            this.inputArea = inputArea;
        }
        public void setOutputArea(JTextArea outputArea) {
            this.outputArea = outputArea;
        }
        public void setPanel(JPanel panel) {
            this.panel = panel;
        }
        public JPanel getPanel() {
            return this.panel;
        }
		public void buildTabs(JTabbedPane tabs) {
            for(int i=0;i<categories.length;i++) {
                tabs.addTab(categories[i], createButtonsOrMenu(categories[i],"button", null, null));
            }
		}
		public String[] getCategories() {
            return categories;
        }
        public ArrayList<Tag> getTags(){
            return tags;
        }
		public void init() {
			Tag tag;
            tags.add(new Tag("Charsets","utf16"));
            tags.add(new Tag("Charsets","utf16be"));
            tags.add(new Tag("Charsets","utf16le"));
            tags.add(new Tag("Charsets","utf32"));
            tags.add(new Tag("Charsets","shift_jis"));
            tags.add(new Tag("Charsets","gb2312"));
            tags.add(new Tag("Charsets","euc_kr"));
            tags.add(new Tag("Charsets","euc_jp"));
            tags.add(new Tag("Charsets","gbk"));
            tags.add(new Tag("Charsets","big5"));
            tag = new Tag("Charsets","charset_convert");
            tag.argument1 = new TagArgument("string","from");
            tag.argument2 = new TagArgument("string","to");
            tags.add(tag);
            tags.add(new Tag("Encode","base32"));
			tags.add(new Tag("Encode","base64"));
			tags.add(new Tag("Encode","html_entities"));
			tags.add(new Tag("Encode","html5_entities"));
            tag = new Tag("Encode","hex");
            tag.argument1 = new TagArgument("string"," ");
            tags.add(tag);
			tags.add(new Tag("Encode","hex_entities"));
			tags.add(new Tag("Encode","hex_escapes"));
			tags.add(new Tag("Encode","octal_escapes"));
			tags.add(new Tag("Encode","dec_entities"));
			tags.add(new Tag("Encode","unicode_escapes"));
			tags.add(new Tag("Encode","css_escapes"));
			tags.add(new Tag("Encode","css_escapes6"));
			tags.add(new Tag("Encode","urlencode"));
            tags.add(new Tag("Encode","php_non_alpha"));
			tags.add(new Tag("Encode","php_chr"));
			tags.add(new Tag("Encode","sql_hex"));
			tags.add(new Tag("Decode","auto_decode"));
			tags.add(new Tag("Decode","d_base32"));
			tags.add(new Tag("Decode","d_base64"));
			tags.add(new Tag("Decode","d_html_entities"));
			tags.add(new Tag("Decode","d_html5_entities"));
			tags.add(new Tag("Decode","d_js_string"));
			tags.add(new Tag("Decode","d_url"));
			tags.add(new Tag("Decode","d_css_escapes"));
			tags.add(new Tag("Decode","d_octal_escapes"));
			tags.add(new Tag("Decode","d_unicode_escapes"));
			tag = new Tag("Convert","dec2hex");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","dec2oct");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","dec2bin");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","hex2dec");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","oct2dec");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Convert","bin2dec");
			tag.argument1 = new TagArgument("string",",");
			tags.add(tag);
			tags.add(new Tag("Convert","ascii2bin"));
			tags.add(new Tag("Convert","bin2ascii"));
			tags.add(new Tag("Convert","ascii2hex"));
			tags.add(new Tag("Convert","hex2ascii"));
			tags.add(new Tag("Convert","ascii2reverse_hex"));
			tags.add(new Tag("String","uppercase"));
			tags.add(new Tag("String","lowercase"));
			tags.add(new Tag("String","capitalise"));
			tags.add(new Tag("String","uncapitalise"));
			tags.add(new Tag("String","from_charcode"));
			tags.add(new Tag("String","to_charcode"));
			tags.add(new Tag("String","reverse"));
			tag = new Tag("String","find");
			tag.argument1 = new TagArgument("string","find");
			tags.add(tag);
			tag = new Tag("String","replace");
			tag.argument1 = new TagArgument("string","find");
			tag.argument2 = new TagArgument("string","replace");
			tags.add(tag);
			tag = new Tag("String","regex_replace");
			tag.argument1 = new TagArgument("string","find");
			tag.argument2 = new TagArgument("string","replace");
			tags.add(tag);
			tag = new Tag("String","repeat");
			tag.argument1 = new TagArgument("int","100");
			tags.add(tag);
			tag = new Tag("String","split_join");
			tag.argument1 = new TagArgument("string","split char");
			tag.argument2 = new TagArgument("string","join char");
			tags.add(tag);
			tags.add(new Tag("Hash","sha1"));
			tags.add(new Tag("Hash","sha256"));
			tags.add(new Tag("Hash","sha384"));
			tags.add(new Tag("Hash","sha512"));
			tags.add(new Tag("Hash","md2"));
			tags.add(new Tag("Hash","md5"));
			tag = new Tag("Math","range");
			tag.argument1 = new TagArgument("int","0");
			tag.argument2 = new TagArgument("int","100");
			tag.argument3 = new TagArgument("int","1");
			tags.add(tag);
			tags.add(new Tag("Math","total"));
			tag = new Tag("Math","arithmetic");
			tag.argument1 = new TagArgument("int","10");
			tag.argument2 = new TagArgument("string","+");
			tag.argument3 = new TagArgument("string",",");
			tags.add(tag);
			tag = new Tag("Math","convert_base");
			tag.argument1 = new TagArgument("string",",");
			tag.argument2 = new TagArgument("int","from");
			tag.argument3 = new TagArgument("int","to");
			tags.add(tag);
            tag = new Tag("Math","random");
            tag.argument1 = new TagArgument("int","10");
            tags.add(tag);
			tag = new Tag("Math","zeropad");
			tag.argument1 = new TagArgument("string",",");
			tag.argument2 = new TagArgument("int","2");
			tags.add(tag);
			tags.add(new Tag("XSS","behavior"));
			tags.add(new Tag("XSS","css_expression"));
			tags.add(new Tag("XSS","datasrc"));
			tags.add(new Tag("XSS","eval_fromcharcode"));
			tags.add(new Tag("XSS","iframe_data_url"));
			tags.add(new Tag("XSS","iframe_src_doc"));
			tags.add(new Tag("XSS","script_data"));
			tags.add(new Tag("XSS","uppercase_script"));
			tags.add(new Tag("XSS","template_eval"));
		}
		public String convertCharset(String input, String to) {
            String output = "";
            try {
                return helpers.bytesToString(input.getBytes(to));
            } catch (UnsupportedEncodingException e) {
                return e.toString();
            }
        }
        public String charset_convert(String input, String from, String to) {
            byte[] inputBytes = input.getBytes();
            byte[] output = new byte[0];
            try {
                output = new String(inputBytes, from).getBytes(to);
            } catch (UnsupportedEncodingException e) {
                return e.toString();
            }
            return helpers.bytesToString(output);
        }
		public String utf16(String input) {
            return convertCharset(input, "UTF-16");
        }
        public String utf16be(String input) {
            return convertCharset(input, "UTF-16BE");
        }
        public String utf16le(String input) {
            return convertCharset(input, "UTF-16LE");
        }
        public String utf32(String input) {
            return convertCharset(input, "UTF-32");
        }
        public String shift_jis(String input) {
            return convertCharset(input, "SHIFT_JIS");
        }
        public String gb2312(String input) {
            return convertCharset(input, "GB2312");
        }
        public String euc_kr(String input) {
            return convertCharset(input, "EUC-KR");
        }
        public String euc_jp(String input) {
            return convertCharset(input, "EUC-JP");
        }
        public String gbk(String input) {
            return convertCharset(input, "GBK");
        }
        public String big5(String input) {
            return convertCharset(input, "BIG5");
        }
		public String html_entities(String str) {
            return HtmlEscape.escapeHtml(str, HtmlEscapeType.HTML4_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
		}
		public String decode_html_entities(String str) {
            return HtmlEscape.unescapeHtml(str);
		}
		public String base32_encode(String str) {
			Base32 base32 = new Base32();
	        return new String(base32.encode(str.getBytes()));
		}
		public String decode_base32(String str) {
			Base32 base32 = new Base32();
			return new String(base32.decode(str.getBytes()));
		}
		public String base64Encode(String str) {
			return helpers.base64Encode(str);
		}
		public String decode_base64(String str) {
			try{
				str = helpers.bytesToString(helpers.base64Decode(str));
			} catch(Exception e){ 
				stderr.println(e.getMessage());
			}
			return str;
		}	
		public String urlencode(String str) {
			try {
	            str = URLEncoder.encode(str, "UTF-8");		    
	        } catch (UnsupportedEncodingException e) {
	        	stderr.println(e.getMessage());
	        }
			return str;
		}
		public String decode_url(String str) {
			try {
	            str = URLDecoder.decode(str, "UTF-8");		          
	        } catch (UnsupportedEncodingException e) {
	        	stderr.println(e.getMessage());
	        }
			return str;
		}
        public String random(String chars, int len) {
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
		public String uppercase(String str) {
			return StringUtils.upperCase(str);
		}
		public String lowercase(String str) {
			return StringUtils.lowerCase(str);
		}
		public String capitalise(String str) {	
			return StringUtils.capitalize(str);
		}
		public String uncapitalise(String str) {
			return StringUtils.uncapitalize(str);
		}
		public String html5_entities(String str) {
			return HtmlEscape.escapeHtml(str, HtmlEscapeType.HTML5_NAMED_REFERENCES_DEFAULT_TO_DECIMAL, HtmlEscapeLevel.LEVEL_3_ALL_NON_ALPHANUMERIC);
		}
		public String decode_html5_entities(String str) {
			return HtmlEscape.unescapeHtml(str);
		}
        public String hex(String str, String separator) {
            return ascii2hex(str," ");
        }
		public String hex_entities(String str) {
			return HtmlEscape.escapeHtml(str, HtmlEscapeType.HEXADECIMAL_REFERENCES,HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		public String dec_entities(String str) {
			return HtmlEscape.escapeHtml(str, HtmlEscapeType.DECIMAL_REFERENCES,HtmlEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		public String hex_escapes(String str) {
			return JavaScriptEscape.escapeJavaScript(str,JavaScriptEscapeType.XHEXA_DEFAULT_TO_UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		public String octal_escapes(String str) {
			StringBuilder converted = new StringBuilder();
			for(int i=0;i<str.length();i++) {
				converted.append("\\" + Integer.toOctalString(Character.codePointAt(str, i)));
			}
			return converted.toString();
		}
		public String decode_octal_escapes(String str) {
			return this.decode_js_string(str);
		}
		public String css_escapes(String str) {
			return CssEscape.escapeCssString(str,CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_COMPACT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		public String css_escapes6(String str) {
			return CssEscape.escapeCssString(str,CssStringEscapeType.BACKSLASH_ESCAPES_DEFAULT_TO_SIX_DIGIT_HEXA, CssStringEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		public String unicode_escapes(String str) {
			return JavaScriptEscape.escapeJavaScript(str,JavaScriptEscapeType.UHEXA, JavaScriptEscapeLevel.LEVEL_4_ALL_CHARACTERS);
		}
		public String php_non_alpha(String input) {
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
		public String php_chr(String str) {
			ArrayList<String> output = new ArrayList<String>();
			for(int i=0;i<str.length();i++) {
				output.add("chr("+Character.codePointAt(str, i)+")");
			}
			return StringUtils.join(output,".");
		}
		public String sql_hex(String str) {
			return "0x"+this.ascii2hex(str, "");
		}
		public String decode_js_string(String str) {
			return JavaScriptEscape.unescapeJavaScript(str);
		}
		public String decode_css_escapes(String str) {
			return CssEscape.unescapeCss(str);
		}
		public String dec2hex(String str, String splitChar) {
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
		public String dec2oct(String str, String splitChar) {
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
		public String dec2bin(String str, String splitChar) {
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
		public String hex2dec(String str, String splitChar) {
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
		public String oct2dec(String str, String splitChar) {			
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
		public String bin2dec(String str, String splitChar) {
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
		public String from_charcode(String str) {
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
		public String to_charcode(String str) {
			ArrayList<Integer> output = new ArrayList<Integer>();
			for(int i=0;i<str.length();i++) {
				output.add(Character.codePointAt(str, i));
			}
			return StringUtils.join(output,",");
		}
		public String ascii2bin(String str) {
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
		public String bin2ascii(String str) {
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
		public String ascii2hex(String str, String separator) {
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
		public String ascii2reverse_hex(String str, String separator) {
			String hex = "";
			List<String> output = new ArrayList<String>();
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
		public String hex2ascii(String str) {
			String output = "";
			if(str.length() % 2 != 0) {
				stderr.println("Invalid hex string");
				return "";
			}
			for(int i=0;i<str.length();i+=2) {
			   try {				   
				   String chars = str.charAt(i)+""+str.charAt(i+1);
				   output += Character.toString((char) Integer.parseInt(chars,16)); 				 
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
			}
			return output;
		}
		public String sha1(String str) {
			return DigestUtils.sha1Hex(str);
		}
		public String sha256(String str) {
			return DigestUtils.sha256Hex(str);
		}
		public String sha384(String str) {
			return DigestUtils.sha384Hex(str);
		}
		public String sha512(String str) {
			return DigestUtils.sha512Hex(str);
		}
		public String md2(String str) {
			return DigestUtils.md2Hex(str);
		}
		public String md5(String str) {
			return DigestUtils.md5Hex(str);
		}
		public String reverse(String str) {
			return new StringBuilder(str).reverse().toString();
		}
		public String find(String str, String find) {
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
		public String replace(String str, String find, String replace) {
			return str.replace(find, replace);
		}
		public String regex_replace(String str, String find, String replace) {
			String output = "";
			try {
				output = str.replaceAll(find, replace.replace("\\","\\\\").replace("$","\\$"));
			} catch(PatternSyntaxException e) {
				 stderr.println(e.getMessage());
			}
			return output;
		}
		public String repeat(String str, int amount) {
			String output = "";
			if(amount > 0 && amount < 10000) {
				for(int i=0;i<amount;i++) {
					output += str;
				}
			}
			return output;
		}
		public String split_join(String str, String splitChar, String joinChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			return StringUtils.join(chars, joinChar);
		}
		public String auto_decode(String str) {
			int repeats = 20;
			int repeat = 0;
			boolean matched;
			String test;
			do {
				matched = false;
				if(Pattern.compile("[01]{4,}\\s+[01]{4,}").matcher(str).find()) {
					str = this.bin2ascii(str);
					matched = true;
				}
				if(!Pattern.compile("[^\\d,\\s]").matcher(str).find() && Pattern.compile("\\d+[,\\s]+").matcher(str).find()) {
					str = this.from_charcode(str);
					matched = true;
				}
				if(Pattern.compile("(?:<style[^>]*>|style[\\s]*=)",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
					str = this.decode_css_escapes(str);
					matched = true;
				}
				if(Pattern.compile("\\\\x[0-9a-f]{2}",Pattern.CASE_INSENSITIVE).matcher(str).find() || Pattern.compile("\\\\[0-9]{1,3}").matcher(str).find() || Pattern.compile("\\\\u[0-9a-f]{4}",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
					str = this.decode_js_string(str);
					matched = true;
				}
				if(Pattern.compile("&[a-zA-Z]+;",Pattern.CASE_INSENSITIVE).matcher(str).find() || Pattern.compile("&#x?[0-9a-f]+;?",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
					str = this.decode_html5_entities(str);
					matched = true;
				}
				if(Pattern.compile("%[0-9a-f]{2}",Pattern.CASE_INSENSITIVE).matcher(str).find()) {
					str = this.decode_url(str);
					matched = true;
				}
				if(Pattern.compile("[a-zA-Z0-9+/]{4,}=*$",Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 4 == 0) {
					test = this.decode_base64(str);
					if(Pattern.compile("^[\\x00-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
						str = test;
						matched = true;	
					}
				}
				if(Pattern.compile("^[a-f0-9/]{4,}$",Pattern.CASE_INSENSITIVE).matcher(str).find() && str.length() % 2 == 0) {
					test = this.hex2ascii(str);
					if(Pattern.compile("^[\\x00-\\x7f]+$",Pattern.CASE_INSENSITIVE).matcher(test).find()) {
						str = test;
						matched = true;	
					}
				}
				if(!matched) {
					break;
				}
				repeat++;
			} while(repeat < repeats);
			return str;
		}
		public String range(String str, int from, int to, int step) {
			ArrayList<Integer> output = new ArrayList<Integer>();
			to++;
			if(from >= 0 && to-from<=10000 && step > 0) {
				for(int i=from;i<to;i+=step) {
					output.add(i);
				}
			}
			return StringUtils.join(output,",");
		}
		public String total(String str) {
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
		public String arithmetic(String str, int amount, String operation, String splitChar) {
			String[] chars = {};
			try {
				chars = str.split(splitChar);
			} catch(PatternSyntaxException e) {
				stderr.println(e.getMessage());				
			}
			ArrayList<String> output = new ArrayList<String>();
			int num = 0;
			for(int i=0;i<chars.length;i++) {
			   try {
				   num = Integer.parseInt(chars[i]);
				   if(operation.equals("+")) {
					   num = num + amount;
				   } else if(operation.equals("-")) {
					   num = num - amount;
				   } else if(operation.equals("/")) {
					   num = num / amount;
				   } else if(operation.equals("*")) {
					   num = num * amount;
				   } else if(operation.equals("%")) {
					   num = num % amount;
				   } else if(operation.equals(">>")) {
					   num = num >> amount;
				   } else if(operation.equals(">>>")) {
					   num = num >>> amount;
				   } else if(operation.equals("<<")) {
					   num = num << amount;
				   }				
				   output.add(""+num);
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
		   }
		   return StringUtils.join(output, ",");
		}
		public String convert_base(String str, String splitChar, int from, int to) {
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
		public String zeropad(String str, String splitChar, int amount) {
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
		public String eval_fromcharcode(String str) {
			return "eval(String.fromCharCode("+this.to_charcode(str)+"))";
		}
		public String behavior(String str) {
			return "<PUBLIC:ATTACH EVENT=onload ONEVENT="+str+" FOR=window />";
		}
		public String css_expression(String str) {
			return "xss:expression(open("+str+"))";
		}
		public String datasrc(String str) {
			return "<xml ID=xss><x><B>&lt;IMG src=1 onerror="+str+"&gt;</B></x></xml><SPAN DATASRC=#xss DATAFLD=B DATAFORMATAS=HTML></SPAN>";
		}
		public String iframe_data_url(String str) {
			return "<iframe src=data:text/html;base64,"+this.base64Encode(str)+">";
		}
		public String uppercase_script(String str) {
			return "<SVG><SCRIPT>"+this.dec_entities(str)+"</SCRIPT></SVG>";
		}
		public String script_data(String str) {
			return "<script src=data:;base64,"+this.base64Encode(str)+"></script>";
		}
		public String iframe_src_doc(String str) {
			return "<iframe srcdoc="+this.html5_entities(str)+"></iframe>";
		}
		public String template_eval(String str) {
			return "eval(`"+str.replaceAll("(.)","$1\\${[]}")+"`)";
		}
		private String callTag(String tag, String output, ArrayList<String> arguments) {
            if(tag.equals("utf16")) {
                output = this.utf16(output);
            } else if(tag.equals("utf16be")) {
                output = this.utf16be(output);
            } else if(tag.equals("utf16le")) {
                output = this.utf16le(output);
            } else if(tag.equals("utf32")) {
                output = this.utf32(output);
            } else if(tag.equals("shift_jis")) {
                output = this.shift_jis(output);
            } else if(tag.equals("gb2312")) {
                output = this.gb2312(output);
            } else if(tag.equals("euc_kr")) {
                output = this.euc_kr(output);
            } else if(tag.equals("euc_jp")) {
                output = this.euc_jp(output);
            } else if(tag.equals("gbk")) {
                output = this.gbk(output);
            } else if(tag.equals("big5")) {
                output = this.big5(output);
            } else if(tag.equals("charset_convert")) {
                output = this.charset_convert(output,this.getString(arguments,0),this.getString(arguments,1));
            } else if(tag.equals("html_entities")) {
				output = this.html_entities(output);
			} else if(tag.equals("d_html_entities")) {
				output = this.decode_html_entities(output);
			} else if(tag.equals("html5_entities")) {
				output = this.html5_entities(output);
            } else if(tag.equals("hex")) {
                output = this.hex(output,this.getString(arguments,0));
			} else if(tag.equals("hex_entities")) {
				output = this.hex_entities(output);
			} else if(tag.equals("hex_escapes")) {
				output = this.hex_escapes(output);
			} else if(tag.equals("octal_escapes")) {
				output = this.octal_escapes(output);
            } else if(tag.equals("php_non_alpha")) {
                output = this.php_non_alpha(output);
			} else if(tag.equals("php_chr")) {
				output = this.php_chr(output);
			} else if(tag.equals("sql_hex")) {
				output = this.sql_hex(output);	
			} else if(tag.equals("auto_decode")) {
				output = this.auto_decode(output);
			} else if(tag.equals("d_octal_escapes")) {
				output = this.decode_octal_escapes(output);	
			} else if(tag.equals("css_escapes")) {
				output = this.css_escapes(output);
			} else if(tag.equals("css_escapes6")) {
				output = this.css_escapes6(output);
			} else if(tag.equals("dec_entities")) {
				output = this.dec_entities(output);
			} else if(tag.equals("unicode_escapes")) {
				output = this.unicode_escapes(output);
			} else if(tag.equals("d_unicode_escapes")) {
				output = this.decode_js_string(output);
			} else if(tag.equals("d_js_string")) {
				output = this.decode_js_string(output);	
			} else if(tag.equals("d_html5_entities")) {
				output = this.decode_html5_entities(output);
			} else if(tag.equals("base32")) {
				output = this.base32_encode(output);
			} else if(tag.equals("d_base32")) {
				output = this.decode_base32(output);	
			} else if(tag.equals("base64")) {
				output = this.base64Encode(output);				
			} else if(tag.equals("d_base64")) {
				output = this.decode_base64(output);	
			} else if(tag.equals("urlencode")) {
				output = this.urlencode(output);
			} else if(tag.equals("d_url")) {
				output = this.decode_url(output);
			} else if(tag.equals("d_css_escapes")) {
				output = this.decode_css_escapes(output);	
			} else if(tag.equals("uppercase")) {
				output = this.uppercase(output);
			} else if(tag.equals("lowercase")) {
				output = this.lowercase(output);
			} else if(tag.equals("capitalise")) {
				output = this.capitalise(output);
			} else if(tag.equals("uncapitalise")) {
				output = this.uncapitalise(output);
			} else if(tag.equals("from_charcode")) {
				output = this.from_charcode(output);
			} else if(tag.equals("to_charcode")) {
				output = this.to_charcode(output);
			} else if(tag.equals("reverse")) {
				output = this.reverse(output);
			} else if(tag.equals("find")) {
				output = this.find(output,this.getString(arguments,0));	
			} else if(tag.equals("replace")) {
				output = this.replace(output,this.getString(arguments,0),this.getString(arguments,1));
			} else if(tag.equals("regex_replace")) {
				output = this.regex_replace(output,this.getString(arguments,0),this.getString(arguments,1));	
			} else if(tag.equals("repeat")) {
				output = this.repeat(output, this.getInt(arguments, 0));
			} else if(tag.equals("split_join")) {
				output = this.split_join(output, this.getString(arguments, 0), this.getString(arguments, 1));	
			} else if(tag.equals("dec2hex")) {
				output = this.dec2hex(output,this.getString(arguments,0));
			} else if(tag.equals("dec2oct")) {
				output = this.dec2oct(output,this.getString(arguments,0));
			} else if(tag.equals("dec2bin")) {
				output = this.dec2bin(output,this.getString(arguments,0));
			} else if(tag.equals("hex2dec")) {
				output = this.hex2dec(output,this.getString(arguments,0));
			} else if(tag.equals("oct2dec")) {
				output = this.oct2dec(output,this.getString(arguments,0));
			} else if(tag.equals("bin2dec")) {
				output = this.bin2dec(output,this.getString(arguments,0));
			} else if(tag.equals("ascii2bin")) {
				output = this.ascii2bin(output);
			} else if(tag.equals("bin2ascii")) {
				output = this.bin2ascii(output);
			} else if(tag.equals("hex2ascii")) {
				output = this.hex2ascii(output);
			} else if(tag.equals("ascii2hex")) {
				output = this.ascii2hex(output,"");
			} else if(tag.equals("ascii2reverse_hex")) {
				output = this.ascii2reverse_hex(output,"");	
			} else if(tag.equals("sha1")) {
				output = this.sha1(output);
			} else if(tag.equals("sha256")) {
				output = this.sha256(output);
			} else if(tag.equals("sha384")) {
				output = this.sha384(output);
			} else if(tag.equals("sha512")) {
				output = this.sha512(output);
			} else if(tag.equals("md2")) {
				output = this.md2(output);
			} else if(tag.equals("md5")) {
				output = this.md5(output);
            } else if(tag.equals("random")) {
                output = this.random(output, this.getInt(arguments,0));
            } else if(tag.equals("range")) {
				output = this.range(output, this.getInt(arguments,0),this.getInt(arguments,1),this.getInt(arguments,2));
			} else if(tag.equals("total")) {
				output = this.total(output);
			} else if(tag.equals("arithmetic")) {
				output = this.arithmetic(output, this.getInt(arguments, 0), this.getString(arguments, 1), this.getString(arguments, 2));
			} else if(tag.equals("convert_base")) {
				output = this.convert_base(output, this.getString(arguments, 0), this.getInt(arguments, 1), this.getInt(arguments, 2));
			} else if(tag.equals("zeropad")) {
				output = this.zeropad(output, this.getString(arguments, 0), this.getInt(arguments, 1));	
			} else if(tag.equals("behavior")) {
				output = this.behavior(output);
			} else if(tag.equals("css_expression")) {
				output = this.css_expression(output);	
			} else if(tag.equals("datasrc")) {
				output = this.datasrc(output);		
			} else if(tag.equals("eval_fromcharcode")) {
				output = this.eval_fromcharcode(output);
			} else if(tag.equals("iframe_data_url")) {
				output = this.iframe_data_url(output);
			} else if(tag.equals("script_data")) {
				output = this.script_data(output);
			} else if(tag.equals("uppercase_script")) {
				output = this.uppercase_script(output);
			} else if(tag.equals("iframe_src_doc")) {
				output = this.iframe_src_doc(output);
			} else if(tag.equals("template_eval")) {
				output = this.template_eval(output);
			}
			return output;
		}
		public void clearTags() {
			String input = inputArea.getText();	                	
			input = input.replaceAll("<@/?\\w+_\\d+(?:[(](?:,?"+argumentsRegex+")*[)])?>","");
      	  	inputArea.setText(input);	                	  	                	  
      	  	inputArea.requestFocus();
		}
		public String convert(String input) {
			String output = input;
			List<String> allMatches = new ArrayList<String>();
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
		public void setInput(String input) {
			inputArea.setText(input);
		}
		public int calculateRealLen(String str) {
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
			Integer output = 0;
			if(args.size() < pos+1) {
				return 0;
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
				return new ArrayList<String>();
			}
			arguments = arguments.substring(1, arguments.length()-1);
			String argument1 = null;
			String argument2 = null;
			String argument3 = null;
			ArrayList<String> convertedArgs = new ArrayList<String>();
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
		private JPanel createButtonsOrMenu(String category, final String type, JMenu parentMenu, final IContextMenuInvocation invocation) {
			JPanel panel = new JPanel(new GridBagLayout());
			GridBagConstraints c = new GridBagConstraints();
			int i = 0;
			int y = 0;
			
			Collections.sort(tags, new Comparator<Tag>() {
		       public int compare(Tag t1, Tag t2) {
		            return t1.name.compareToIgnoreCase(t2.name);
		        }

		    });
			
			for(final Tag tagObj:tags) {
				final Tag tag = tagObj;
                final JButton btn = new JButton(tagObj.name);
                final JMenuItem menu = new JMenuItem(tagObj.name);
				ActionListener actionListener;
				if(category == tagObj.category) {
					if(i == 10) {
						y++;
						i = 0;
					}

					if(type.equals("button")) {
                        c.fill = GridBagConstraints.HORIZONTAL;
                        c.weightx = 0.5;
                        c.gridx = i;
                        c.gridy = y;
                        c.ipady = 0;
                        c.gridwidth = 1;
                        btn.setBackground(Color.decode("#005a70"));
                        btn.setForeground(Color.white);
                        btn.putClientProperty("tag", tagObj);
                    }

                    actionListener = new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            String selectedText = null;
                            if(type.equals("button")) {
                                selectedText = inputArea.getSelectedText();
                                if (selectedText == null) {
                                    selectedText = "";
                                }
                            }
                            String tagStart = "<@"+tagObj.name+"_"+tagCounter;
                            if(tag.argument1 != null) {
                                tagStart += "(";
                            }
                            if(tag.argument1 != null) {
                                if(tag.argument1.type.equals("int")) {
                                    tagStart += tag.argument1.value;
                                } else if(tag.argument1.type.equals("string")) {
                                    tagStart += "\"" + tag.argument1.value + "\"";
                                }
                            }
                            if(tag.argument2 != null) {
                                tagStart += ",";
                                if(tag.argument2.type.equals("int")) {
                                    tagStart += tag.argument2.value;
                                } else if(tag.argument2.type.equals("string")) {
                                    tagStart += "\"" + tag.argument2.value + "\"";
                                }
                            }
                            if(tag.argument3 != null) {
                                tagStart += ",";
                                if(tag.argument3.type.equals("int")) {
                                    tagStart += tag.argument3.value;
                                } else if(tag.argument3.type.equals("string")) {
                                    tagStart += "\"" + tag.argument3.value + "\"";
                                }
                            }
                            if(tag.argument1 != null) {
                                tagStart += ")";
                            }
                            tagStart += ">";
                            String tagEnd = "<@/"+tagObj.name+"_"+tagCounter+">";
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
                        }
                    };

                    if(type.equals("button")) {
                        btn.addActionListener(actionListener);
                        panel.add(btn,c);
                    } else {
                        menu.addActionListener(actionListener);
                        parentMenu.add(menu);
                    }

					i++;
				}
			}
			return panel;
		}
	}

}
