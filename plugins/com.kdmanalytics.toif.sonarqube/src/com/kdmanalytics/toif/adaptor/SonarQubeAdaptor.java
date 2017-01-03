
package com.kdmanalytics.toif.adaptor;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.commons.lang3.ArrayUtils;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kdmanalytics.toif.common.exception.ToifException;
import com.kdmanalytics.toif.framework.files.IFileResolver;
import com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor;
import com.kdmanalytics.toif.framework.toolAdaptor.AdaptorOptions;
import com.kdmanalytics.toif.framework.toolAdaptor.Language;
import com.kdmanalytics.toif.framework.utils.FindingCreator;

/**
 * class for the SonarQube adaptor.
 * 
 * @author "Nikhil Pawar <nikhilpawar@yahoo.in>"
 * 
 */
public class SonarQubeAdaptor extends AbstractAdaptor {

	/**
	 * the logger.
	 */
	private static final Logger LOG = LoggerFactory.getLogger(SonarQubeAdaptor.class);

	/**
	 * By default we expect the executable to be in path
	 */
	private String execPath = "sonarlint.bat";

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorName ()
	 */
	@Override
	public String getAdaptorName() {
		return "SonarQube";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorDescription()
	 */
	@Override
	public String getAdaptorDescription() {
		return "SonarQube will check your Java code and find bugs, inconsistencies and synchronization problems by doing data flow analysis and building the lock graph.";
	}

	/**
	 * create the List using the FindingCreator of elements.
	 * 
	 * @throws ToifException
	 */
	@Override
	public ArrayList<com.kdmanalytics.toif.framework.xmlElements.entities.Element> parse(java.io.File process,
			AdaptorOptions options, IFileResolver resolver, boolean[] validLines, boolean unknownCWE)
			throws ToifException {
		System.out.println("****CWE discovered****");
		
		String msg="";
		try {
			// new finding creator
			com.kdmanalytics.toif.framework.xmlElements.entities.File file = resolver.getDefaultFile();
					
			
			FindingCreator creator = new FindingCreator(getProperties(), getAdaptorName(), unknownCWE);
			
			File out = new File(options.getOutputDirectory()+  "\\"+options.getOutputDirectory().getName().replace('.', '_') + ".html");
			
			Document doc = Jsoup.parse(out, "UTF-8");

			Elements children;
			

			Elements issues = doc.getElementsByAttributeValue("class", "vtitle");
			for (Element issue : issues) {
				children = issue.children();
				for (Element child : children) {
					if (child.hasClass("icon-severity-critical")) {
						System.out.println("****CWE discovered****");
						
						String lineNumber = "", ln="", id = "";
						
						lineNumber = issue.parent().parent().parent().id();

						ln = lineNumber.substring(lineNumber.lastIndexOf('V') + 1, lineNumber.length());

						msg = child.nextElementSibling().text();

						id = msg.trim();
						id= id.replaceAll("\"", "");
						id = id.replaceAll("\\.", "");
						id = id.replaceAll(" ", "_");

						System.out.println(ln);
						System.out.println(id);
						System.out.println(msg);						
							
						creator.create(msg, id, Integer.parseInt(ln), null, null, file, null, null);
					}
				}

			}
			
			return creator.getElements();

		} catch (Exception e) {
			LOG.error("sonar errors", e);
			throw new ToifException(msg, e);
		}

	}

	@Override
	public String[] runToolCommands(AdaptorOptions options, String[] otherOpts) {

		// this is where the output of the tool is going to be written in order
		// for us to collect it.

		// the required commands to run the tool.
		String[] allCommands = new String[10];

		String execPath = this.execPath;
		if (options.getExecutablePath() != null)
			execPath = options.getExecutablePath().getAbsolutePath();

		final String[] commands = {
		 execPath, "--src",options.getInputFile().getName(),
		 "--html-report",options.getOutputDirectory() +"\\" +options.getOutputDirectory().getName() + ".html"};
		
		allCommands = ArrayUtils.addAll(commands, otherOpts);

		System.out.println("commands " + Arrays.toString(commands));
		System.out.println("All commands " + Arrays.toString(allCommands));

		return allCommands;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorVendorAddress()
	 */
	@Override
	public String getAdaptorVendorAddress() {
		return "UTA, Arlington,TX";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorVendorDescription()
	 */
	@Override
	public String getAdaptorVendorDescription() {
		return "KDM Analytics is a security assurance company providing products and services for threat risk assessment and management, due diligence assessments, and information and data assurance. Leveraging our decades of experience in static analysis, reverse engineering and formal methods, we have created breakthrough products for the automated and systematic investigation of code, data and networks.";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorVendorEmail()
	 */
	@Override
	public String getAdaptorVendorEmail() {
		return "info@kdmanalytics.com";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorVendorName()
	 */
	@Override
	public String getAdaptorVendorName() {
		return "UTA secure programming-the team";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getAdaptorVendorPhone()
	 */
	@Override
	public String getAdaptorVendorPhone() {
		return "1-000-000-1010";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorDescription()
	 */
	@Override
	public String getGeneratorDescription() {
		return "sonarqube will check your Java code and find bugs, inconsistencies and synchronization problems by doing data flow analysis and building the lock graph.";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorName ()
	 */
	@Override
	public String getGeneratorName() {
		return "sonarqube";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorVendorAddress()
	 */
	@Override
	public String getGeneratorVendorAddress() {
		return "http://jlint.sourceforge.net/";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorVendorDescription()
	 */
	@Override
	public String getGeneratorVendorDescription() {
		return "We develop tools for web pages with dynamic content of medium size";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorVendorEmail()
	 */
	@Override
	public String getGeneratorVendorEmail() {
		return "c.artho@aist.go.jp";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorVendorName()
	 */
	@Override
	public String getGeneratorVendorName() {
		return "Nikhil Pawar";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorVendorPhone()
	 */
	@Override
	public String getGeneratorVendorPhone() {
		return "+100 000 000";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.kdmanalytics.toif.framework.toolAdaptor.AbstractAdaptor#
	 * getGeneratorVersion()
	 */
	@Override
	public String getGeneratorVersion() {
		return "Assumed 3.0.0";
	}

	@Override
	public String getRuntoolName() {
		return "sonarqube";
	}

	@Override
	public Language getLanguage() {
		return Language.JAVA;
	}

	@Override
	public boolean acceptsDOptions() {
		return false;
	}

	@Override
	public boolean acceptsIOptions() {
		return false;
	}
}
