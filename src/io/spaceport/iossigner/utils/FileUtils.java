package io.spaceport.iossigner.utils;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

public final class FileUtils {
	protected static void close(Closeable stream) {
		try {
			stream.close();
		} catch(IOException e) {
			// I don't know what needs to be done if a stream failed to close
		}
	}
	
	public static void copyFile(File sourceFile, File destFile) throws IOException {
	    if(!destFile.exists())
	        destFile.createNewFile();

	    FileChannel source = null;
	    FileChannel destination = null;

	    try {
	        source = new FileInputStream(sourceFile).getChannel();
	        destination = new FileOutputStream(destFile).getChannel();
	        destination.transferFrom(source, 0, source.size());
	    } finally {
	        if(source != null)
	        	close(source);
	        if(destination != null)
	        	close(destination);
	    }
	}
	
	public static byte[] readFully(String fileName) throws IOException {
		return readFully(new File(fileName));
	}
	
	public static byte[] readFully(File file) throws IOException {
		FileInputStream source = null;
		try {
			source = new FileInputStream(file);
			
			int read;
			byte[] buffer = new byte[1024];
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			
			while((read = source.read(buffer)) >= 0)
				result.write(buffer, 0, read);
			
			return result.toByteArray();
		} finally {
			if(source != null)
				close(source);
		}
	}
}
