package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.Document;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringEscapeUtils;
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

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

	private IExtensionHelpers helpers;
	private JPanel panel;
	private JTextArea inputArea;
	private JTextArea outputArea;
	private PrintWriter stderr;
	private Hackvertor hv;
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
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		helpers = callbacks.getHelpers();
		stderr = new PrintWriter(callbacks.getStderr(), true);
		callbacks.setExtensionName("Hackvertor");
		callbacks.registerContextMenuFactory(this);
		
		 SwingUtilities.invokeLater(new Runnable() 
	        {
	            @Override
	            public void run()
	            {	   
	            	JTabbedPane tabs = new JTabbedPane();
	            	hv = new Hackvertor();
	            	hv.init();
	            	hv.buildTabs(tabs);
	            		     	
	            	JLabel logoLabel = new JLabel(createImageIcon("/burp/images/logo.gif","logo"));
	            	final JLabel hexView = new JLabel("",SwingConstants.CENTER);	                
	                hexView.setOpaque(true);
	            	JPanel buttonsPanel = new JPanel(new GridBagLayout());	            
	            	panel = new JPanel(new GridBagLayout());  
	            	inputArea = new JTextArea(20,10);    
	            	inputArea.setLineWrap(true);	            
	            	inputArea.setMinimumSize(new Dimension(300,500));	
	            	final UndoManager undo = new UndoManager();
            	    Document doc = inputArea.getDocument();
            	    
            	   // Listen for undo and redo events            	
            	   doc.addUndoableEditListener(new UndoableEditListener() {
            	       public void undoableEditHappened(UndoableEditEvent evt) {
            	           undo.addEdit(evt.getEdit());
            	       }
            	   });
            	    
            	   // Create an undo action and add it to the text component
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
            	    
            	   // Bind the undo action to ctl-Z
            	   inputArea.getInputMap().put(KeyStroke.getKeyStroke("control Z"), "Undo");
            	    
            	   // Create a redo action and add it to the text component
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
	            	inputScroll.setMinimumSize(new Dimension(300,500));
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
                	DocumentListener documentListener = new DocumentListener() {
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
						@Override
						public void caretUpdate(CaretEvent e) {
							String selectedText = inputArea.getSelectedText();
							if(selectedText != null) {			
								hexView.setBackground(Color.decode("#FFF5BF"));
								hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
								String output = hv.ascii2hex(selectedText, " ");
								hexView.setText(output);
							} else {
								hexView.setText("");
								hexView.setBackground(new Color(0,0,0,0));
								hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 0));
							}
						}
	                });
	                outputArea = new JTextArea(20,10);
	                outputArea.setMinimumSize(new Dimension(300,500));
	                outputArea.setLineWrap(true);
	                outputArea.addCaretListener(new CaretListener()
	                {	               
						@Override
						public void caretUpdate(CaretEvent e) {
							String selectedText = outputArea.getSelectedText();
							if(selectedText != null) {			
								hexView.setBackground(Color.decode("#FFF5BF"));
								hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
								String output = hv.ascii2hex(selectedText, " ");
								hexView.setText(output);
							} else {
								hexView.setText("");
								hexView.setBackground(new Color(0,0,0,0));
								hexView.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 0));
							}
						}
	                });
	                final JScrollPane outputScroll = new JScrollPane(outputArea);
	                outputScroll.setMinimumSize(new Dimension(300,500));
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
	            	final JButton convertButton = new JButton("Convert");
	                convertButton.setBackground(Color.decode("#005a70"));
	                convertButton.setForeground(Color.white);
	                convertButton.addActionListener(new ActionListener() {
	                  public void actionPerformed(ActionEvent e) {	                	
	                	  outputArea.setText(hv.convert(inputArea.getText()));
	                	  outputArea.selectAll();
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
	                	  String input = inputArea.getText();
	                	  String argumentsRegex = "(?:[(](?:,?(?:\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\"))+[)])?";
	                	  input = input.replaceAll("<@/?\\w+_\\d+"+argumentsRegex+">","");
	                	  inputArea.setText(input);	                	  	                	  
	                	  inputArea.requestFocus();
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
	                buttonsPanel.add(clearButton,createConstraints(0,0,1));	               
	                buttonsPanel.add(clearTagsButton,createConstraints(1,0,1));	              	               
	                buttonsPanel.add(swapButton,createConstraints(2,0,1));	              
	                buttonsPanel.add(selectInputButton,createConstraints(3,0,1));	              
	                buttonsPanel.add(selectOutputButton,createConstraints(4,0,1));	              
	                buttonsPanel.add(convertButton,createConstraints(5,0,1));	               	                
	                GridBagConstraints c = createConstraints(0,0,4);
	                c.anchor = GridBagConstraints.EAST;	
	                c.fill = GridBagConstraints.NONE;
	                c.ipadx = 20;
	                c.ipady = 20;
	                panel.add(logoLabel,c);
	                panel.add(tabs,createConstraints(0,1,4));
	                JPanel inputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
	                c = createConstraints(0,0,1);
	                c.insets = new Insets(5,5,5,5);	               
	                c.weightx = 0;	        
	                c.anchor = GridBagConstraints.WEST;
	                inputLabelsPanel.add(inputLabel,c);
	                c = createConstraints(1,0,1);
	                c.insets = new Insets(5,5,5,5);
	                c.weightx = 0;
	                c.anchor = GridBagConstraints.WEST;
	                inputLabelsPanel.add(inputLenLabel,c);
	                c = createConstraints(2,0,1);
	                c.insets = new Insets(5,5,5,5);
	                c.weightx = 0;
	                c.anchor = GridBagConstraints.WEST;
	                inputLabelsPanel.add(inputRealLenLabel,c);
	                panel.add(inputLabelsPanel,createConstraints(0,2,1));
	                panel.add(inputScroll,createConstraints(0,3,1));
	                JPanel outputLabelsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
	                c = createConstraints(0,0,1);
	                c.insets = new Insets(5,5,5,5);
	                c.weightx = 0;
	                outputLabelsPanel.add(outputLabel,c);
	                c = createConstraints(1,0,1);
	                c.insets = new Insets(5,5,5,5);
	                c.weightx = 0;
	                outputLabelsPanel.add(outputLenLabel,c);
	                c = createConstraints(2,0,1);
	                c.insets = new Insets(5,5,5,5);
	                c.weightx = 0;
	                outputLabelsPanel.add(outputRealLenLabel,c);
	                panel.add(outputLabelsPanel,createConstraints(1,2,1));
	                panel.add(outputScroll,createConstraints(1,3,1));	 	                
	                panel.add(buttonsPanel,createConstraints(0,4,1));
	                c = createConstraints(0,5,4);
	                c.insets = new Insets(5,5,5,5);	          
	                panel.add(hexView,c);
	                c = createConstraints(0,6,1);
	                c.weighty = 1;
	                panel.add(new JPanel(),c);
	                callbacks.customizeUiComponent(inputArea);
	                callbacks.customizeUiComponent(outputArea);
	                callbacks.customizeUiComponent(panel);	              
	                callbacks.addSuiteTab(BurpExtender.this);
	            }
	        });
		
	}
	@Override
	public String getTabCaption() {
		return "Hackvertor";
	}
	
	@Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		int[] bounds = invocation.getSelectionBounds();
		
		switch (invocation.getInvocationContext()) {
			case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
			case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
			case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
			case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
			break;
			default:
				return null;
		}
		
		if(bounds[0] == bounds[1]) {
			return null;
		}
        List<JMenuItem> menu = new ArrayList<>();
        Action hackvertorAction = new HackvertorAction("Send to Hackvertor", invocation);
        JMenuItem sendToHackvertor = new JMenuItem(hackvertorAction); 
        menu.add(sendToHackvertor);
        return menu;
    }
	class HackvertorAction extends AbstractAction {

        IContextMenuInvocation invocation;
        private static final long serialVersionUID = 1L;
        
        public HackvertorAction(String text, IContextMenuInvocation invocation) {
            super(text);
            this.invocation = invocation;	          
        }
        
        @Override
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
        		//JTabbedPane tabs = panel.getParent().getParent();
        		/*
        		Container tabComponent = panel.getParent();
        		int tabIndex = tabs.indexOfTabComponent(tabComponent);
        		tabs.setSelectedIndex(tabIndex);
        		*/ 
        		
        		hv.setInput((new String(message).substring(bounds[0], bounds[1])).trim()); 
        	}
        }
        
    }
	public void alert(String msg) {
		JOptionPane.showMessageDialog(null, msg);
	}
	@Override
	public Component getUiComponent() {
        return panel;
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
		private ArrayList<Tag> tags = new ArrayList<Tag>();
		public void buildTabs(JTabbedPane tabs) {
			tabs.addTab("Encode", createButtons("Encode"));
        	tabs.addTab("Decode", createButtons("Decode"));
        	tabs.addTab("Convert", createButtons("Convert"));
        	tabs.addTab("String", createButtons("String"));
        	tabs.addTab("Hash", createButtons("Hash"));
        	tabs.addTab("Math", createButtons("Math"));
        	tabs.addTab("XSS", createButtons("XSS"));
		}
		public void init() {
			Tag tag;
			tags.add(new Tag("Encode","base32"));
			tags.add(new Tag("Encode","base64"));
			tags.add(new Tag("Encode","html_entities"));
			tags.add(new Tag("Encode","html5_entities"));
			tags.add(new Tag("Encode","hex_entities"));
			tags.add(new Tag("Encode","hex_escapes"));
			tags.add(new Tag("Encode","octal_escapes"));
			tags.add(new Tag("Encode","dec_entities"));
			tags.add(new Tag("Encode","unicode_escapes"));
			tags.add(new Tag("Encode","css_escapes"));
			tags.add(new Tag("Encode","css_escapes6"));
			tags.add(new Tag("Encode","urlencode"));
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
			tags.add(new Tag("Convert","dec2hex"));
			tags.add(new Tag("Convert","dec2oct"));
			tags.add(new Tag("Convert","dec2bin"));
			tags.add(new Tag("Convert","hex2dec"));
			tags.add(new Tag("Convert","oct2dec"));
			tags.add(new Tag("Convert","bin2dec"));
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
			tags.add(new Tag("Hash","sha1"));
			tags.add(new Tag("Hash","sha256"));
			tags.add(new Tag("Hash","sha384"));
			tags.add(new Tag("Hash","sha512"));
			tags.add(new Tag("Hash","md2"));
			tags.add(new Tag("Hash","md5"));
			tag = new Tag("Math","range");
			tag.argument1 = new TagArgument("int","0");
			tag.argument2 = new TagArgument("int","100");
			tags.add(tag);
			tags.add(new Tag("Math","total"));
			tags.add(new Tag("XSS","behavior"));
			tags.add(new Tag("XSS","css_expression"));
			tags.add(new Tag("XSS","datasrc"));
			tags.add(new Tag("XSS","eval_fromcharcode"));
			tags.add(new Tag("XSS","iframe_data_url"));
			tags.add(new Tag("XSS","script_data"));
			tags.add(new Tag("XSS","uppercase_script"));
		}
		public String html_entities(String str) {
			return StringEscapeUtils.escapeHtml4(str);
		}
		public String decode_html_entities(String str) {
			return StringEscapeUtils.unescapeHtml4(str);
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
		public String dec2hex(String str) {
			try{
				str = Integer.toHexString(Integer.parseInt(str));
			} catch(NumberFormatException e){ 
				stderr.println(e.getMessage()); 
			}
			return str;
		}
		public String dec2oct(String str) {
			try{
				str = Integer.toOctalString(Integer.parseInt(str));
			} catch(NumberFormatException e){ 
				stderr.println(e.getMessage()); 
			}
			return str;
		}
		public String dec2bin(String str) {
			try{
				str = Integer.toBinaryString(Integer.parseInt(str));
			} catch(NumberFormatException e){ 
				stderr.println(e.getMessage()); 
			}
			return str;
		}
		public String hex2dec(String str) {
			try{
				str = Integer.toString(Integer.parseInt(str,16));
			} catch(NumberFormatException e){ 
				stderr.println(e.getMessage()); 
			}
			return str;
		}
		public String oct2dec(String str) {
			try{
				str = Integer.toString(Integer.parseInt(str,8));
			} catch(NumberFormatException e){ 
				stderr.println(e.getMessage()); 
			}
			return str;
		}
		public String bin2dec(String str) {
			try{
				str = Integer.toString(Integer.parseInt(str,2));
			} catch(NumberFormatException e){ 
				stderr.println(e.getMessage()); 
			}
			return str;
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
			 Matcher m = Pattern.compile(find).matcher(str);
			 while (m.find()) {
			   allMatches.add(m.group());
			 }
			 return StringUtils.join(allMatches,",");
		}
		public String replace(String str, String find, String replace) {
			return str.replace(find, replace);
		}
		public String regex_replace(String str, String find, String replace) {
			return str.replaceAll(find, replace.replace("\\","\\\\").replace("$","\\$"));
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
				if(!matched) {
					break;
				}
				repeat++;
			} while(repeat < repeats);
			return str;
		}
		public String range(String str, int from, int to) {
			ArrayList<Integer> output = new ArrayList<Integer>();
			to++;
			if(from >= 0 && to-from<=10000) {
				for(int i=from;i<to;i++) {
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
		private String callTag(String tag, String output, ArrayList<String> arguments) {
			if(tag.equals("html_entities")) {
				output = this.html_entities(output);
			} else if(tag.equals("d_html_entities")) {
				output = this.decode_html_entities(output);
			} else if(tag.equals("html5_entities")) {
				output = this.html5_entities(output);
			} else if(tag.equals("hex_entities")) {
				output = this.hex_entities(output);
			} else if(tag.equals("hex_escapes")) {
				output = this.hex_escapes(output);
			} else if(tag.equals("octal_escapes")) {
				output = this.octal_escapes(output);
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
			} else if(tag.equals("dec2hex")) {
				output = this.dec2hex(output);
			} else if(tag.equals("dec2oct")) {
				output = this.dec2oct(output);
			} else if(tag.equals("dec2bin")) {
				output = this.dec2bin(output);
			} else if(tag.equals("hex2dec")) {
				output = this.hex2dec(output);
			} else if(tag.equals("oct2dec")) {
				output = this.oct2dec(output);
			} else if(tag.equals("bin2dec")) {
				output = this.bin2dec(output);
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
			} else if(tag.equals("range")) {
				output = this.range(output, this.getInt(arguments,0),this.getInt(arguments,1));
			} else if(tag.equals("total")) {
				output = this.total(output);
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
			}
			return output;
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
				 String argumentsRegex = "(?:[(](?:,?(?:\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\"))+[)])?";
				 m = Pattern.compile("<@"+tagNameWithID+"("+argumentsRegex+")>([\\d\\D]*?)<@/"+tagNameWithID+">").matcher(output);
				 if(m.find()) {
					arguments = m.group(1);
					code = m.group(2); 
				 } 	
				 String result = this.callTag(tagName,code,this.parseArguments(arguments));
				 output = output.replaceAll("<@"+tagNameWithID+argumentsRegex+">[\\d\\D]*?<@/"+tagNameWithID+">", result.replace("\\","\\\\").replace("$","\\$"));
			 }
			return output;			
		}
		public void setInput(String input) {
			inputArea.setText(input);
			inputArea.selectAll();
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
			String argumentRegex = "((?:,?(?:\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")))(,(?:,?(?:\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")))?(,(?:,?(?:\\d+|'(?:\\\\'|[^']*)'|\"(?:\\\\\"|[^\"]*)\")))?";			
			Matcher m = Pattern.compile(argumentRegex).matcher(arguments);
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
		private JPanel createButtons(String category) {
			panel = new JPanel(new GridBagLayout());
			GridBagConstraints c = new GridBagConstraints();
			int i = 0;
			int y = 0;
			for(Tag tagObj:tags) {
				final Tag tag = tagObj;
				if(category == tagObj.category) {
					if(i == 10) {
						y++;
						i = 0;
					}
					c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = i;	             
	                c.gridy = y;
	                c.ipady = 0;	
	                c.gridwidth = 1;
	                final JButton btn = new JButton(tagObj.name);
	                btn.setBackground(Color.decode("#005a70"));	            
	            	btn.setForeground(Color.white);
	            	btn.putClientProperty("tag", tagObj);
	            	btn.addActionListener(new ActionListener() {
	                  public void actionPerformed(ActionEvent e) {
	                	  String selectedText = inputArea.getSelectedText();
	                	  if(selectedText == null) {
	                		  selectedText = "";	        
	                	  }
	                	  String tagStart = "<@"+btn.getText()+"_"+tagCounter;
	                	  if(tag.argument1 != null) {
	                		  tagStart += "(";
	                	  }
	                	  if(tag.argument1 != null) {	                		 
	                		  if(tag.argument1.type == "int") {
	                			  tagStart += tag.argument1.value;
	                		  } else if(tag.argument1.type == "string") {
	                			  tagStart += "\"" + tag.argument1.value + "\"";
	                		  }
	                	  }
	                	  if(tag.argument2 != null) {	                		 
	                		  tagStart += ",";
	                		  if(tag.argument2.type == "int") {
	                			  tagStart += tag.argument2.value;
	                		  } else if(tag.argument2.type == "string") {
	                			  tagStart += "\"" + tag.argument2.value + "\"";
	                		  }
	                	  }
	                	  if(tag.argument3 != null) {
	                		  tagStart += ",";
	                		  if(tag.argument3.type == "int") {
	                			  tagStart += tag.argument3.value;
	                		  } else if(tag.argument3.type == "string") {
	                			  tagStart += "\"" + tag.argument3.value + "\"";
	                		  }
	                	  }
	                	  if(tag.argument1 != null) {
	                		  tagStart += ")";
	                	  }
	                	  tagStart += ">";
	                	  String tagEnd = "<@/"+btn.getText()+"_"+tagCounter+">";	                	 
	                	  inputArea.replaceSelection(tagStart+selectedText+tagEnd);
	                	  tagCounter++;	 
	                	  outputArea.setText(hv.convert(inputArea.getText()));
	                	  outputArea.selectAll();
	                  }
	                });
					panel.add(btn,c);
					i++;
				}
			}
			return panel;
		}
	}
	
}
