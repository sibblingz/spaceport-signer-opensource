package io.spaceport.iossigner.darwin;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSNumber;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListParser;

public class AppBundle {
	protected String path;
	protected NSDictionary infoPlist;
	
	private class ResourceRule {
		public ResourceRule(String r, boolean a) {
			rule = r;
			accept = a;
		}
		
		String rule;
		boolean accept;
	}
	
	public boolean valid() {
		return infoPlist != null;
	}
	
	public void open(File bundle) throws Exception {
		open(bundle.getPath());
	}
	
	public void open(String bundlePath) throws Exception {
		File bundleDirectory = new File(bundlePath);
		if(!bundleDirectory.exists())
			throw new FileNotFoundException(bundlePath + " (No such file or directory)");
		if(!bundleDirectory.isDirectory())
			throw new FileNotFoundException(bundlePath + " (Not a directory)");
		
		path = bundleDirectory.getPath();
		readInfoPlist();
	}
	
	public String bundlePath() {
		return path;
	}

	public String identifier() {
		if(!valid())
			return null;
		
		return infoPlist.objectForKey("CFBundleIdentifier").toString();
	}
	
	public String executable() {
		if(!valid())
			return null;
		
		return infoPlist.objectForKey("CFBundleExecutable").toString();
	}
	
	public String executablePath() {
		if(!valid())
			return null;

		return new File(path, executable()).getPath();
	}
	
	public String resourceRulesPath() {
		if(!valid())
			return null;

		return new File(path, infoPlist.objectForKey("CFBundleResourceSpecification").toString()).getPath();
	}
	
	public String[] filesInBundle() {
		if(!valid())
			return null;

		return recursiveFileList(path);
	}
	
	public String[] resources() throws Exception {
		if(!valid())
			return null;

		// Compile rules
		NSDictionary rules = (NSDictionary)((NSDictionary)PropertyListParser.parse(new File(resourceRulesPath()))).objectForKey("rules");
		
		// Priority -> {Rule, Acceptance}, sorted from high to low
		TreeMap<Double, ResourceRule > compiledRules = new TreeMap<Double, ResourceRule >(new Comparator<Double >() {
		    public int compare(Double d1, Double d2) {
		        double delta = d2 - d1;
		        
		        if(delta > 0)
		        	return 1;
		        if(delta < 0)
		        	return -1;
		        
		        return 0;
		    }
		});
		
		// Compile rules according to the plist specification
		for(String rule:rules.allKeys()) {
			NSObject ruleDefinition = rules.objectForKey(rule);
			if(ruleDefinition.getClass().equals(NSNumber.class)) {
				if(((NSNumber)ruleDefinition).type() == NSNumber.BOOLEAN)
					compiledRules.put(0.0, new ResourceRule(rule, !((NSNumber)rules.objectForKey(rule)).boolValue()));
			}
			if(ruleDefinition.getClass().equals(NSDictionary.class)) {
				boolean omit = true;
				double weight = 0.0;
				
				NSDictionary ruleInfo = (NSDictionary)rules.objectForKey(rule);
				
				if(ruleInfo.objectForKey("omit") != null)
					omit = ((NSNumber)ruleInfo.objectForKey("omit")).boolValue();
				if(ruleInfo.objectForKey("weight") != null)
					weight = ((NSNumber)ruleInfo.objectForKey("weight")).doubleValue();
				
				compiledRules.put(weight, new ResourceRule(rule, omit));
			}
		}
		
		String[] bundleFiles = filesInBundle();
		List<String > result = new ArrayList<String >();
		for(String path:bundleFiles) {
			boolean omit = true;
			for(Map.Entry<Double, ResourceRule > rule:compiledRules.entrySet()) {
				if(rule.getValue().rule.equals(".*")) {
					omit = rule.getValue().accept; break;
				}

				if(rule.getValue().rule.equals(path)) {
					omit = rule.getValue().accept; break;
				}
			}
			
			if(omit)
				continue;

			result.add(path);
		}
		
		// Executable should be removed from asset list
		result.remove(executable());
		
		// Apple sorts their files by name, so do we
		Collections.sort(result);
		
		return result.toArray(new String[result.size()]);
	}
	
	public String pathForFile(String path) {
		return bundlePath() + "/" + path;
	}
	
	protected void readInfoPlist() throws Exception {
		infoPlist = (NSDictionary)PropertyListParser.parse(new File(path + "/Info.plist"));
	}
	
	private String[] recursiveFileList(String directoryPath) {
		List<String > directoryContent = new ArrayList<String >();
		
		// List all files in directory
		String[] content = new File(directoryPath).list();
		for(String fileName:content) {
			String filePath = directoryPath + "/" + fileName;
			if(new File(filePath).isDirectory()) {
				String[] files = recursiveFileList(filePath);
				for(String path:files)
					directoryContent.add(path);
			} else {
				directoryContent.add(filePath);
			}
		}
		
		// Clean up to bundle path basename (To get relative pathnames)
		String[] result = new String[directoryContent.size()];
		for(int i=0; i<directoryContent.size(); ++i) {
			String filePath = directoryContent.get(i);
			if(filePath.startsWith(path))
				filePath = filePath.substring(path.length() + 1); // Including forward slash
			
			result[i] = filePath;
		}
		
		return result;
	}
}
