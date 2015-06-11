package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.Document;
import javax.swing.undo.CannotRedoException;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;

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
	            	inputLabel.setOpaque(true);
	            	inputLabel.setBackground(Color.decode("#FFF5BF"));	
	            	inputLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
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
                      	inputLabel.setText("Input:"+len); 
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
	                outputArea = new JTextArea(20,10);
	                outputArea.setMinimumSize(new Dimension(300,500));
	                outputArea.setLineWrap(true);	            
	                final JScrollPane outputScroll = new JScrollPane(outputArea);
	                outputScroll.setMinimumSize(new Dimension(300,500));
	                final JLabel outputLabel = new JLabel("Output:");
	                outputLabel.setOpaque(true);
	                outputLabel.setBackground(Color.decode("#FFF5BF"));
	                outputLabel.setBorder(BorderFactory.createLineBorder(Color.decode("#FF9900"), 1));
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
                      	outputLabel.setText("Output:"+len); 
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
	                	  input = input.replaceAll("<@/?\\w+_\\d+>","");
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
	                c = createConstraints(0,2,1);
	                c.insets = new Insets(5,5,5,5);
	                panel.add(inputLabel,c);	                
	                panel.add(inputScroll,createConstraints(0,3,1));
	                c = createConstraints(1,2,1);
	                c.insets = new Insets(5,5,5,5);
	                panel.add(outputLabel,c);	             
	                panel.add(outputScroll,createConstraints(1,3,1));	 	                
	                panel.add(buttonsPanel,createConstraints(0,4,1));
	                c = createConstraints(0,5,1);
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
		Tag(String tagCategory, String tagName) {
			this.category = tagCategory;
			this.name = tagName;		
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
		}
		public void init() {
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
			tags.add(new Tag("Decode","decode_base64"));
			tags.add(new Tag("Decode","decode_html_entities"));
			tags.add(new Tag("Decode","decode_html5_entities"));
			tags.add(new Tag("Decode","decode_js_string"));
			tags.add(new Tag("Decode","decode_url"));
			tags.add(new Tag("Decode","decode_css_escapes"));
			tags.add(new Tag("Decode","decode_octal_escapes"));
			tags.add(new Tag("Decode","decode_unicode_escapes"));
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
			tags.add(new Tag("String","uppercase"));
			tags.add(new Tag("String","lowercase"));
			tags.add(new Tag("String","capitalise"));
			tags.add(new Tag("String","uncapitalise"));
			tags.add(new Tag("String","from_charcode"));
			tags.add(new Tag("String","to_charcode"));
			tags.add(new Tag("String","reverse"));
			tags.add(new Tag("Hash","sha1"));
			tags.add(new Tag("Hash","sha256"));
			tags.add(new Tag("Hash","sha384"));
			tags.add(new Tag("Hash","sha512"));
			tags.add(new Tag("Hash","md2"));
			tags.add(new Tag("Hash","md5"));
		}
		public String html_entities(String str) {
			return StringEscapeUtils.escapeHtml4(str);
		}
		public String decode_html_entities(String str) {
			return StringEscapeUtils.unescapeHtml4(str);
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
		   String[] chars = str.split(",");
		   String output = "";
		   if(str.length() == 1) {
			   try {
				   output = Character.toString((char) Integer.parseInt(str));
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
			   return output;
		   } else {
			   for(int i=0;i<chars.length;i++) {
				   try {
					   output += Character.toString((char) Integer.parseInt(chars[i]));
				   } catch(NumberFormatException e){ 
						stderr.println(e.getMessage()); 
				   }
			   }
			   return output;
		   }
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
		public String ascii2hex(String str) {
			String output = "";
			for(int i=0;i<str.length();i++) {
			   try {
				   output += Integer.toHexString(Character.codePointAt(str, i));				 
			   } catch(NumberFormatException e){ 
					stderr.println(e.getMessage()); 
			   }
			}
			return output;
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
		private String callTag(String tag, String output) {
			if(tag.equals("html_entities")) {
				output = this.html_entities(output);
			} else if(tag.equals("decode_html_entities")) {
				output = this.decode_html_entities(output);
			} else if(tag.equals("html5_entities")) {
				output = this.html5_entities(output);
			} else if(tag.equals("hex_entities")) {
				output = this.hex_entities(output);
			} else if(tag.equals("hex_escapes")) {
				output = this.hex_escapes(output);
			} else if(tag.equals("octal_escapes")) {
				output = this.octal_escapes(output);
			} else if(tag.equals("decode_octal_escapes")) {
				output = this.decode_octal_escapes(output);	
			} else if(tag.equals("css_escapes")) {
				output = this.css_escapes(output);
			} else if(tag.equals("css_escapes6")) {
				output = this.css_escapes6(output);
			} else if(tag.equals("dec_entities")) {
				output = this.dec_entities(output);
			} else if(tag.equals("unicode_escapes")) {
				output = this.unicode_escapes(output);
			} else if(tag.equals("decode_unicode_escapes")) {
				output = this.decode_js_string(output);
			} else if(tag.equals("decode_js_string")) {
				output = this.decode_js_string(output);	
			} else if(tag.equals("decode_html5_entities")) {
				output = this.decode_html5_entities(output);	
			} else if(tag.equals("base64")) {
				output = this.base64Encode(output);
			} else if(tag.equals("decode_base64")) {
				output = this.decode_base64(output);
			} else if(tag.equals("urlencode")) {
				output = this.urlencode(output);
			} else if(tag.equals("decode_url")) {
				output = this.decode_url(output);
			} else if(tag.equals("decode_css_escapes")) {
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
				output = this.ascii2hex(output);	
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
				 String tagName = tagNameWithID.replaceAll("_\\d+$","");
				 m = Pattern.compile("<@"+tagNameWithID+">([\\d\\D]*?)<@/"+tagNameWithID+">").matcher(output);
				 if(m.find()) {
					code = m.group(1); 
				 } 	
				 String result = this.callTag(tagName,code);
				 output = output.replaceAll("<@"+tagNameWithID+">[\\d\\D]*?<@/"+tagNameWithID+">", result.replace("\\","\\\\").replace("$","\\$"));
			 }
			return output;			
		}
		public void setInput(String input) {
			inputArea.setText(input);
			inputArea.selectAll();
		}
		private JPanel createButtons(String category) {
			panel = new JPanel(new GridBagLayout());
			GridBagConstraints c = new GridBagConstraints();
			int i = 0;
			for(Tag tagObj:tags) {
				if(category == tagObj.category) {
					c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = i;
	                c.gridy = 0;
	                c.ipady = 0;	
	                c.gridwidth = 1;
	                final JButton btn = new JButton(tagObj.name);
	                btn.setBackground(Color.decode("#005a70"));	            
	            	btn.setForeground(Color.white);
	            	btn.addActionListener(new ActionListener() {
	                  public void actionPerformed(ActionEvent e) {
	                	  String selectedText = inputArea.getSelectedText();
	                	  if(selectedText == null) {
	                		  selectedText = inputArea.getText();
	                		  inputArea.setText("");
	                	  }
	                	  String tagStart = "<@"+btn.getText()+"_"+tagCounter+">";
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
