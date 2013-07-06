package io.spaceport.iossigner.ui;


public abstract class Command {
	private final String commandString;
	private final String quickInfo;
	
	public Command(String commandString, String quickInfo) {
		this.commandString = commandString;
		this.quickInfo = quickInfo;
	}
	
	/**
	 * Retrieve the command string for this sub command
	 */
	public String getCommandString() {
		return commandString;
	}

	/**
	 * Retrieve the command quick info
	 */
	public String getQuickInfo() {
		return quickInfo;
	}
	
	/**
	 * Execute sub command with arguments, return return code
	 */
	public abstract int execute(String[] args);

	/**
	 * Show usage for this sub command
	 * This function must exit with status code 1
	 */
	public void showUsage() {
		System.exit(1);
	}
}
