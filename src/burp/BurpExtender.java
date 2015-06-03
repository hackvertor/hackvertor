package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.*;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTabbedPane;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.net.URLDecoder;

public class BurpExtender implements IBurpExtender, ITab {
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JPanel panel;
	private JTextArea inputArea;
	private JTextArea outputArea;
	
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("Hackvertor");
		 SwingUtilities.invokeLater(new Runnable() 
	        {
	            @Override
	            public void run()
	            {	   
	            	JTabbedPane tabs = new JTabbedPane();
	            	final Hackvertor hv = new Hackvertor();
	            	hv.init();
	            	hv.buildTabs(tabs);
	            	       	
	            	JPanel buttonsPanel = new JPanel(new GridBagLayout());
	            	panel = new JPanel(new GridBagLayout());
	            	
	            	GridBagConstraints c = new GridBagConstraints();	            	
	            	inputArea = new JTextArea();	         
	            	final JLabel inputLabel = new JLabel("Input:");
	            	                          	              	            	
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
	                inputArea.setPreferredSize(new Dimension(750, 500));	                	              
	                outputArea = new JTextArea();
	                final JLabel outputLabel = new JLabel("Output:");
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
	                outputArea.setPreferredSize(new Dimension(750, 500));
	            	panel.setPreferredSize(new Dimension(800,600));	            	
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
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 0;
	                c.gridy = 0;
	                c.ipady = 0;
	                buttonsPanel.add(clearButton,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 1;
	                c.gridy = 0;
	                c.ipady = 0;
	                buttonsPanel.add(swapButton,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 2;
	                c.gridy = 0;
	                c.ipady = 0;
	                buttonsPanel.add(selectInputButton,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 3;
	                c.gridy = 0;
	                c.ipady = 0;
	                buttonsPanel.add(selectOutputButton,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 4;
	                c.gridy = 0;
	                c.ipady = 0;
	                buttonsPanel.add(convertButton,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 0;
	                c.gridy = 0;
	                c.ipady = 0;
	                c.gridwidth = 4;
	                panel.add(tabs,c);
	              	c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 0;
	                c.gridy = 1;
	                c.ipady = 0;
	                c.gridwidth = 1;
	                panel.add(inputLabel,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 0;
	                c.gridy = 2;	              
	                c.ipady = 100;
	                c.gridwidth = 1;
	                panel.add(inputArea,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 1;
	                c.gridy = 1;
	                c.ipady = 0;
	                c.gridwidth = 1;
	                panel.add(outputLabel,c);
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 1;
	                c.gridy = 2;
	                c.ipady = 100;
	                c.gridwidth = 1;
	                panel.add(outputArea,c);	 
	                c.fill = GridBagConstraints.HORIZONTAL;
	                c.weightx = 0.5;
	                c.gridx = 0;
	                c.gridy = 3;
	                c.ipady = 0;	
	                c.gridwidth = 1;
	                panel.add(buttonsPanel,c);	                            
	                callbacks.customizeUiComponent(panel);
	                
	                callbacks.addSuiteTab(BurpExtender.this);	          
	            }
	        });
		
	}
	public String getTabCaption() {
		return "Hackvertor";
	}
	
	public Component getUiComponent()
    {
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
		}
		public void init() {
			tags.add(new Tag("Encode","base64"));
			tags.add(new Tag("Encode","htmlentities"));
			tags.add(new Tag("Encode","hex"));
			tags.add(new Tag("Encode","urlencode"));
			tags.add(new Tag("Decode","decode_base64"));
			tags.add(new Tag("Decode","decode_htmlentities"));
			tags.add(new Tag("Decode","decode_urlencode"));
		}
		private String callTag(String tag, String output) {
			if(tag.equals("htmlentities")) {
				output = output.replace("<", "&lt;");
				output = output.replace("&", "&amp;");
			} else if(tag.equals("base64")) {
				return helpers.base64Encode(output);
			} else if(tag.equals("decode_base64")) {
				try{
					output = helpers.bytesToString(helpers.base64Decode(output));
				} catch(Exception e){ 
					output = e.toString(); 
				}
			} else if(tag.equals("urlencode")) {
				try {
		            output = URLEncoder.encode(output, "UTF-8");		          
		        } catch (UnsupportedEncodingException ex) {
		            output = ex.toString();
		        }
			} else if(tag.equals("decode_urlencode")) {
				try {
		            output = URLDecoder.decode(output, "UTF-8");		          
		        } catch (UnsupportedEncodingException ex) {
		            output = ex.toString();
		        }
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
				 output = output.replaceAll("<@"+tagNameWithID+">[\\d\\D]*?<@/"+tagNameWithID+">", result);
			 }
			return output;			
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
	                	  }
	                	  String tagStart = "<@"+btn.getText()+"_"+tagCounter+">";
	                	  String tagEnd = "<@/"+btn.getText()+"_"+tagCounter+">";	                	 
	                	  inputArea.replaceSelection(tagStart+selectedText+tagEnd);
	                	  tagCounter++;
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
