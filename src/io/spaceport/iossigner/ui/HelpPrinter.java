package io.spaceport.iossigner.ui;

import java.util.LinkedHashMap;
import java.util.Map;

public class HelpPrinter {
	private static String repeat(String character, int n) {
		return new String(new char[n]).replace("\0", character);
	}
	
	public static class Entry {
		public Entry(String name, String quickInfo) {
			this.name = name;
			this.quickInfo = quickInfo;
		}
		
		public String name;
		public String quickInfo;
	}
	
	protected int padding;
	protected int prefixSpace;
	protected Map<String, HelpPrinter.Entry> parameterList = new LinkedHashMap<String, HelpPrinter.Entry>();
	
	public HelpPrinter(int prefixSpace, int padding) {
		this.prefixSpace = prefixSpace;
		this.padding = padding;
	}
	
	public HelpPrinter addEntry(HelpPrinter.Entry entry) {
		parameterList.put(entry.name, entry);
		return this;
	}
		
	public void print() {
		int actualPadding = padding;
		for(Map.Entry<String, HelpPrinter.Entry> entry : parameterList.entrySet()) {
			String action = entry.getKey();
			actualPadding = Math.max(actualPadding, ((action.length() / padding) + 1) * padding);
		}
		
		for(Map.Entry<String, HelpPrinter.Entry> entry : parameterList.entrySet()) {
			String action = entry.getKey();
			
			// Get padding for action name for pretty-printing
			int pad = ((action.length() / actualPadding) + 1) * actualPadding - action.length();
			System.out.format("%s%s%s%s\n", repeat(" ", prefixSpace), action, repeat(" ", pad), entry.getValue().quickInfo);
		}
	}
}