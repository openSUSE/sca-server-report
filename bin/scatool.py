##############################################################################
# scatool.py - Supportconfig Analysis (SCA) Tool
# Copyright (c) 2014-2020 SUSE LLC
#
# Description:  Runs and analyzes local or remote supportconfigs
# Modified:     2020 Oct 23

##############################################################################
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.
#
#  Authors/Contributors:
#     David Hamner (ke7oxh@gmail.com)
#     Jason Record (jason.record@suse.com)
#
##############################################################################
SVER = '1.0.9-1.dev22'

##########################################################################################
# Python Imports
##########################################################################################
import subprocess
import os
import sys
import glob
import uuid
import tarfile
import shutil
import datetime
import socket
import time
import getopt
import re
import smtplib
import email
import email.encoders
import email.mime.text
import email.mime.base

##########################################################################################
# HELP FUNCTIONS
##########################################################################################
def title():
	print "################################################################################"
	print "#   SCA Tool v" + SVER
	print "################################################################################"
	print

def usage():
	print "Usage:"
	print " -h       Displays this screen"
	print " -s       Analyze the local server"
	print " -a path  Analyze the supportconfig directory or archive"
	print "          The path may also be an IP address of a server to analyze"
	print " -o path  HTML report output directory (OUTPUT_PATH)"
	print " -e list  Send HTML report to email address(es) provided. Comma separated list."
	print " -k       Keep archive files (ARCHIVE_MODE)"
	print " -p       Print a pattern summary"
	print " -v       Verbose output (LOGLEVEL)"
	print

title()
##########################################################################################
# Environment and Global Variables
##########################################################################################
#setup environment and PWD
try:
	os.chdir(os.environ["PWD"])
	setup = os.environ["SCA_READY"]
except Exception:
	print >> sys.stderr, "Error: Do not run directly; use scatool"
	print >> sys.stderr
	usage()
	sys.exit()
if not setup:
	usage()
	print >> sys.stderr
	sys.exit()

try:
	SCA_PATTERN_PATH = str(os.environ["SCA_PATTERN_PATH"])
except Exception:
	SCA_PATTERN_PATH = "/usr/lib/sca/patterns"

try:
	ARCHIVE_MODE = int(os.environ["ARCHIVE_MODE"])
except Exception:
	ARCHIVE_MODE = 0

try:
	REMOTE_SC_PATH = str(os.environ["REMOTE_SC_PATH"])
except Exception:
	REMOTE_SC_PATH = "/var/log"

try:
	OUTPUT_PATH = str(os.environ["OUTPUT_PATH"])
except Exception:
	OUTPUT_PATH = ""

try:
	OUTPUT_EMAIL_LIST = str(os.environ["OUTPUT_EMAIL_LIST"])
except Exception:
	OUTPUT_EMAIL_LIST = ""

try:
	LOGLEVEL_NORMAL = int(os.environ["LOGLEVEL_NORMAL"])
except Exception:
	LOGLEVEL_NORMAL = 1

try:
	LOGLEVEL_VERBOSE = int(os.environ["LOGLEVEL_VERBOSE"])
except Exception:
	LOGLEVEL_VERBOSE = 2

try:
	LOGLEVEL = int(os.environ["LOGLEVEL"])
except Exception:
	LOGLEVEL = LOGLEVEL_NORMAL

#setup globals
global results
global patternErrorList
global knownClasses
global HTML
global outputPath
global htmlOutputFile
global emailAddrList
global KeepArchive
global serverName
global verboseMode
global analysisDateTime
global patternStats
global patternDict
knownClasses = []
results = []
patternErrorList = []
patternStats = {
	'Total': 0,
	'Applied': 0,
	'Errors': 0,
	'Crit': 0,
	'Warn': 0,
	'Recc': 0,
	'Succ': 0
}

if( ARCHIVE_MODE > 0 ):
	KeepArchive = True
else:
	KeepArchive = False

if( LOGLEVEL == LOGLEVEL_VERBOSE ):
	verboseMode = True
else:
	verboseMode = False

if( len(OUTPUT_PATH) > 0 ):
	outputPath = OUTPUT_PATH
else:
	outputPath = ""

if( len(OUTPUT_EMAIL_LIST) > 0 ):
	emailAddrList = OUTPUT_EMAIL_LIST
else:
	emailAddrList = ""

serverName = "Unknown"
analysisDateTime = datetime.datetime.now()

#order dependent list of pattern output elements
RESULT_ELEMENT = ["META_CLASS", "META_CATEGORY", "META_COMPONENT", "PATTERN_ID", "PRIMARY_LINK", "OVERALL", "OVERALL_INFO", "META_LINK_"]

##########################################################################################
# HTML REPORT FUNCTIONS
##########################################################################################
##########################################################################################
# getHeader
##########################################################################################
#returns html code. This is the part about the server.

def getHeader(*arg):
	global serverName
	global analysisDateTime
	#reset variables
	DISTRO = 0
	supportconfigVersion = ""
	oesVersion = ""
	oesPatchLevel = ""
	OS = ""
	OES = ""
	INFO = ""
	VER = ""
	OSVersion = ""
	patchLevel = ""
	kernelVersion = ""
	hardWare = ""
	virtualization = ""
	vmIdentity = ""
	PRODUCTS = [['Distribution:', 'Unknown', 'Service Pack:', 'Unknown']]
	#set timeAnalysis (example: 2014-04-10 17:45:15)
	timeAnalysis = str(analysisDateTime.year) + "-" + str(analysisDateTime.month).zfill(2) + "-" + str(analysisDateTime.day).zfill(2) + " " + str(analysisDateTime.hour).zfill(2) + ":" + str(analysisDateTime.minute).zfill(2) + ":" + str(analysisDateTime.second).zfill(2)
	timeArchiveRun = "0000-00-00 00:00:00"
	returnHTML = ""

	#set archive name if given
	if len(arg) == 3:
		arcName = arg[2]
	else:
		arcName = ""

	#load basic-environment.txt
	try:
		with open(arg[0] + "/basic-environment.txt") as f:
			BASIC_ENV = f.read().splitlines()
	except:
		BASIC_ENV = []

	#read basic-environment line by line to pull out data.
	IN_DATE = False
	IN_UNAME = False
	IN_RELEASE = False
	IN_OES_RELEASE = False
	IN_FILR = False
	for line in BASIC_ENV:
		if "Script Version:" in line:
			supportconfigVersion = line.split(':')[-1].strip()
		elif line.startswith("Hardware:"):
			hardWare = line.split(":")[1].strip()
		elif line.startswith("Hypervisor:"):
			virtualization = line.split(":")[1].strip()
		elif line.startswith("Identity:"):
			vmIdentity = line.split(":")[1].strip()
		elif "/bin/date" in line:
			IN_DATE = True
		elif "/bin/uname -a" in line:
			IN_UNAME = True
		elif "/etc/SuSE-release" in line:
			IN_RELEASE = True
		elif "/etc/novell-release" in line:
			IN_OES_RELEASE = True
		elif "/etc/Novell-VA-release" in line:
			IN_FILR = True
		elif( IN_DATE ):
			if "#==[" in line:
				IN_DATE = False
			else:
				dateLine = line
				dateLine = re.sub("\s+", " ", dateLine.rstrip("\n")) # replace multiple whitespace with single space
				tmp = dateLine.split() # split into list based on a space
				if( len(tmp) >= 4 ):
					tmpMonth = tmp[1].strip()
					if "Jan" in tmpMonth:
						tmpMonth = "01"
					elif "Feb" in tmpMonth:
						tmpMonth = "02"
					elif "Mar" in tmpMonth:
						tmpMonth = "03"
					elif "Apr" in tmpMonth:
						tmpMonth = "04"
					elif "May" in tmpMonth:
						tmpMonth = "05"
					elif "Jun" in tmpMonth:
						tmpMonth = "06"
					elif "Jul" in tmpMonth:
						tmpMonth = "07"
					elif "Aug" in tmpMonth:
						tmpMonth = "08"
					elif "Sep" in tmpMonth:
						tmpMonth = "09"
					elif "Oct" in tmpMonth:
						tmpMonth = "10"
					elif "Nov" in tmpMonth:
						tmpMonth = "11"
					elif "Dec" in tmpMonth:
						tmpMonth = "12"
					timeArchiveRun = tmp[-1].strip() + "-" + tmpMonth + "-" + tmp[2].strip().zfill(2) + " " + tmp[3].strip()
					IN_DATE = False
		elif( IN_UNAME ):
			if "#==[" in line:
				IN_UNAME = False
			else:
				tmp = line.split()
				if( len(tmp) >= 3 ):
					kernelVersion = tmp[2].strip()
					serverName = tmp[1].strip()
					IN_UNAME = False
		elif( IN_RELEASE ):
			if "#==[" in line:
				IN_RELEASE = False
				PRODUCTS[DISTRO][1] = str(OS)
				PRODUCTS[DISTRO][3] = str(patchLevel)
			else:
				if( len(OS) > 0 ):
					if line.lower().startswith("version"):
						OSVersion = line.split('=')[-1].strip()
					elif line.lower().startswith("patchlevel"):
						patchLevel = line.split('=')[-1].strip()
				else:
					OS = line.strip()
		elif( IN_OES_RELEASE):
			if "#==[" in line:
				IN_OES_RELEASE = False
				PRODUCTS.insert(1, ['Product:', OES, 'Service Pack:', oesPatchLevel])
			else:
				if( len(OES) > 0 ):
					if line.lower().startswith("version"):
						OESVersion = line.split('=')[-1].strip().split('.')[0]
					elif line.lower().startswith("patchlevel"):
						oesPatchLevel = line.split('=')[-1].strip()
				else:
					OES = line.strip()
		elif( IN_FILR ):
			if "#==[" in line:
				IN_FILR = False
				if( INFO and VER ):
					PRODUCTS.append(['Product:', INFO, 'Version:', VER])
				INFO = ""
				VER = ""
			else:
				if line.lower().startswith("product"):
					INFO = line.split('=')[-1].strip()
				elif line.lower().startswith("version"):
					VER = line.split('=')[-1].strip()

	del BASIC_ENV

	#load summary.xml
	try:
		with open(arg[0] + "/summary.xml") as f:
			SUMMARY = f.read().splitlines()
	except:
		SUMMARY = []

	PROD_START = re.compile(r'<product\s|<product>', re.IGNORECASE)
	PROD_END = re.compile(r'</product>', re.IGNORECASE)
	IN_PRODUCT = False

	#detect SLE for VMWARE
	PROD_NAME = re.compile(r'<summary>SUSE Linux Enterprise Server .* for VMware</summary>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'Product': None, 'Version': None}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['Product'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['Version'] = re.search(r'>(.+?)<', LINE).group(1)
				except:
					True
			if( INFO['Product'] and INFO['Version'] ):
				IN_PRODUCT = False
				PRODUCTS[DISTRO][1] = INFO['Product']
				PRODUCTS[DISTRO][3] = INFO['Version']
				INFO = {'Product': None, 'Version': None}
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	#detect SLE for SAP
	PROD_NAME = re.compile(r'<description>SUSE LINUX Enterprise Server for SAP Applications</description>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'Product': None, 'Version': None}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['Product'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['Version'] = re.search(r'>(.+?)<', LINE).group(1)
				except:
					True
			if( INFO['Product'] and INFO['Version'] ):
				IN_PRODUCT = False
				PRODUCTS[DISTRO][1] = INFO['Product']
				PRODUCTS[DISTRO][3] = INFO['Version']
				INFO = {'Product': None, 'Version': None}
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	#get HAE information
	PROD_NAME = re.compile(r'<summary>SUSE Linux Enterprise High Availability Extension.*</summary>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'Product': None, 'Version': None}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['Product'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['Version'] = re.search(r'>(.+?)<', LINE).group(1)
				except:
					True
			if( INFO['Product'] and INFO['Version'] ):
				IN_PRODUCT = False
				PRODUCTS.append(['Product:', INFO['Product'], 'Version:', INFO['Version']])
				INFO = {'Product': None, 'Version': None}
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	#get SUSE Manager information
	PROD_NAME = re.compile(r'<name>SUSE-Manager.*</name>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'Product': None, 'Version': None}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['Product'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['Version'] = re.search(r'>(.+?)<', LINE).group(1)
				except:
					True
			if( INFO['Product'] and INFO['Version'] ):
				IN_PRODUCT = False
				PRODUCTS.append(['Product:', INFO['Product'], 'Version:', INFO['Version']])
				INFO = {'Product': None, 'Version': None}
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	del SUMMARY

#	print "["
#	for INFO in PRODUCTS:
#		print " " + str(INFO)
#	print "]"
#	sys.exit()

	#create HTML from the data we just got
	returnHTML += '<H1>Supportconfig Analysis Report</H1>\n'
	returnHTML += '<H2><HR />Server Information</H2>\n'

	returnHTML += '<TABLE CELLPADDING="5">\n'
	returnHTML += '<TR><TD><B>Analysis Date:</B></TD><TD>'
	returnHTML += timeAnalysis
	returnHTML += '</TD></TR>\n'
	returnHTML += '<TR><TD><B>Supportconfig Run Date:</B></TD><TD>'
	returnHTML += timeArchiveRun
	returnHTML += '</TD></TR>\n'
	returnHTML += '<TR><TD><B>Supportconfig File:</B></TD><TD>'
	returnHTML += arcName
	returnHTML += '</TD></TR>\n'
	returnHTML += '</TABLE>\n'

	returnHTML += '<TABLE CELLPADDING="5">\n'

	returnHTML += '<TR><TD>&nbsp;</TD></TR>\n'

	returnHTML += '<TR></TR>\n'

	#Server name and hardWare
	returnHTML += '<TR><TD><B>Server Name:</B></TD><TD>'
	returnHTML += serverName
	returnHTML += '</TD><TD><B>Hardware:</B></TD><TD>'
	returnHTML += hardWare
	returnHTML += '</TD></TR>\n'

	#Products included in supportconfig
	for INFO in PRODUCTS:
		returnHTML += '<TR><TD><B>'
		returnHTML += str(INFO[0])
		returnHTML += '</B></TD><TD>'
		returnHTML += str(INFO[1])
		returnHTML += '</TD><TD><B>'
		returnHTML += str(INFO[2])
		returnHTML += '</B></TD><TD>'
		returnHTML += str(INFO[3])
		returnHTML += '</TD></TR>\n'

	if virtualization != "None" and virtualization != "":
		#hypervisor stuff
		returnHTML += '<TR><TD><B>Hypervisor:</B></TD><TD>'
		returnHTML += virtualization
		returnHTML += '</TD><TD><B>Identity:</B></TD><TD>'
		returnHTML += vmIdentity
		returnHTML += '</TD></TR>\n'

	#kernel Version and Supportconfig version
	returnHTML += '<TR><TD><B>Kernel Version:</B></TD><TD>'
	returnHTML += kernelVersion
	returnHTML += '</TD><TD><B>Supportconfig Version:</B></TD><TD>'
	returnHTML += supportconfigVersion
	returnHTML += '</TD></TR>\n'
	returnHTML += '</TABLE>\n'
	returnHTML += '<HR />\n'
	return returnHTML


##########################################################################################
# getFooter
##########################################################################################
#creates an HTML footer string for the HTML report
#called by getHtml
#returns HTML code
def getFooter():
	global patternStats
	returnHTML = '\n\n<HR />\n\n<TABLE WIDTH="100%">\n<TR>'\
		'<TD ALIGN="left" WIDTH="30%">Client: scatool v'\
		+ SVER +\
		' (Report Generated by: SCA Tool)</TD>'\
		'<TD ALIGN="center">Patterns Evaluated: '\
		+ str(patternStats['Total']) +\
		', Appliable to Server: '\
		+ str(patternStats['Applied']) +\
		'</TD><TD ALIGN="right" WIDTH="30%">'\
		'<A HREF="https://www.suse.com/support/" ALT="SUSE Technical Support" TARGET="_blank">SUSE Technical Support</A></TD>'\
		'</TR>\n</TABLE>\n'

	return returnHTML


##########################################################################################
# getClasses
##########################################################################################
#find all class Names in results
#does not return anything
#side effect: set "knownClasses"
def getClasses():
	global knownClasses
	global results
	#reset knownClasses
	knownClasses = []
	IDX_RESULTS_CLASS = 1
	IDX_VALUE = 1
	for i in range(len(results)):
		if not (results[i][IDX_RESULTS_CLASS].split("=")[IDX_VALUE] in knownClasses):
			knownClasses.append(results[i][IDX_RESULTS_CLASS].split("=")[IDX_VALUE])


##########################################################################################
# getHtml
##########################################################################################
#create the html code. :)
#called by analyze
#must be run after runPats
def getHtml(OutPutFile, archivePath, archiveFile):
	global knownClasses
	global results
	global HTML
	global serverName
	
	#get known classes
	getClasses()
	
	
	#reset	stuff
	Main_Link = ""
	links = ""
	HTML = ""
	HTML_HEADER = ""

	#html script...
	script = "<SCRIPT>\n\
	function toggle(className)\n\
	{\n\
	className = className.replace(/ /g,\".\");\n\
	var elements = document.querySelectorAll(\".\" + className); for(var i=0; i<elements.length; i++)\n\
	{\n\
		if( elements[i].style.display=='none' )\n\
			{\n\
				elements[i].style.display = '';\n\
			}\n\
			else\n\
			{\n\
				elements[i].style.display = 'none';\n\
			}\n\
	}\n\
	}\n\n\
	function showPattern(patternOutput,patternLocation)\n\
	{\n\
	alert(patternOutput + \"\\n\\n\" + \"Pattern: \" + patternLocation);\n\
	}\n\
	</SCRIPT>"

	#add stuff to html.. :)
	HTML += script + "\n"
	HTML += "</HEAD>" + "\n"
	
	#get header html
	HTML += "<BODY BGPROPERTIES=FIXED BGCOLOR=\"#FFFFFF\" TEXT=\"#000000\">" + "\n"
	HTML += getHeader(archivePath, OutPutFile, archiveFile)

	# getHeader probes the archive for serverName, so the header has to be retrieved after getHeader is called.
	# temporarily storing header in HTML_HEADER
	#html top bit:
	HTML_HEADER += "<!DOCTYPE html>" + "\n"
	HTML_HEADER += "<HTML>" + "\n"
	HTML_HEADER += "<HEAD>" + "\n"
	HTML_HEADER += "<TITLE>SCA Report for " + serverName + "</TITLE>" + "\n"
	HTML_HEADER += "<STYLE TYPE=\"text/css\">" + "\n"
	HTML_HEADER += "  a {text-decoration: none}  /* no underlined links */" + "\n"
	HTML_HEADER += "  a:link {color:#0000FF;}  /* unvisited link */" + "\n"
	HTML_HEADER += "  a:visited {color:#0000FF;}  /* visited link */" + "\n"
	HTML_HEADER += "</STYLE>" + "\n"
	HTML_HEADER += HTML
	HTML = HTML_HEADER
	
	#Critical table
	HTML += '<H2>Conditions Evaluated as Critical<A NAME="Critical"></A></H2>' + "\n"
	HTML += '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML += '<TR COLOR="#000000"><TH BGCOLOR="#FF0000"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#FF0000"></TH></TR>' + "\n"
	HTML += getTableHtml(4)
	HTML += "</TABLE>" + "\n"
	
	#Warning table
	HTML += '<H2>Conditions Evaluated as Warning<A NAME="Warning"></A></H2>' + "\n"
	HTML += '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML += '<TR COLOR="#000000"><TH BGCOLOR="#FFFF00"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#FFFF00"></TH></TR>' + "\n"
	HTML += getTableHtml(3)
	HTML += "</TABLE>" + "\n"
	
	#Recommended table
	HTML += '<H2>Conditions Evaluated as Recommended<A NAME="Recommended"></A></H2>' + "\n"
	HTML += '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML += '<TR COLOR="#000000"><TH BGCOLOR="#1975FF"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#1975FF"></TH></TR>' + "\n"
	HTML += getTableHtml(1)
	HTML += "</TABLE>" + "\n"
	
	#Success table
	HTML += '<H2>Conditions Evaluated as Success<A NAME="Success"></A></H2>' + "\n"
	HTML += '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML += '<TR COLOR="#000000"><TH BGCOLOR="#00FF00"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#00FF00"></TH></TR>' + "\n"
	HTML += getTableHtml(0)
	HTML += "</TABLE>" + "\n"
	
	HTML += getFooter()

	#HTML end stuff
	HTML += "</BODY>" + "\n"
	HTML += "</HTML>" + "\n"
	
	#write HTML to the output file
	fh = open(OutPutFile, "w")
	fh.write(HTML)
	fh.close()


##########################################################################################
# getTableHtml
##########################################################################################
#takes a status(critical (4), warning (3), etc) and returns the corresponding table... in html
def getTableHtml(val):
	global patternStats
	#reset number of hits. ( a hit in this case is a result that matches "val")
	numHits = 0
	severityCount = 0
	#set the color.
	if val == 4:
		#red (critical)
		severityTag = "Critical "
		severityIdx = 'Crit'
		color = "FF0000"
	elif val == 3:
		#yellow (warning)
		severityTag = "Warning "
		severityIdx = 'Warn'
		color = "FFFF00"
	elif val == 1:
		#blue.. ish (recommended)
		severityTag = "Recommended "
		severityIdx = 'Recc'
		color = "1975FF"
	elif val == 0:
		#green (success)
		severityTag = "Success "
		severityIdx = 'Succ'
		color ="00FF00"
	else:
		#fallback (gray)
		severityTag = ""
		color = "222222"
	 

	IDX_KEY = 0
	IDX_VALUE = 1
	IDX_RESULTS_PATTERN_PATH = 0
	IDX_RESULTS_CLASS = 1
	IDX_RESULTS_CATEGORY = 2
	IDX_RESULTS_COMPONENT = 3
	IDX_RESULTS_PATTERN_ID = 4
	IDX_RESULTS_PRIMARY_LINK = 5
	IDX_RESULTS_OVERALL = 6
	IDX_RESULTS_OVERALL_INFO = 7
	returnString = ""
	tmpReturn = ""
	
	#sort by known classes
	for Class in knownClasses:
		numHits = 0
		tmpReturn = ""
		#for all results
		for i in range(len(results)):
			#for results of a pattern
			if results[i][IDX_RESULTS_CLASS].split("=")[IDX_VALUE] == Class and int(results[i][IDX_RESULTS_OVERALL].split("=")[IDX_VALUE]) == val:
				numHits += 1
				severityCount += 1
				#find main link
				Main_Link = ""
				for j in range(len(results[i])):
					#if main link
					if results[i][j].split('=')[IDX_KEY] == results[i][IDX_RESULTS_PRIMARY_LINK].split("=")[IDX_VALUE]:
						
						#remove the stuff before the first "="
						tmp = results[i][j].split('=')
						del tmp[0]
						for LinkPart in tmp:
							Main_Link = Main_Link + "=" + LinkPart
						Main_Link = Main_Link.strip("=")
						#clean up the "=" leftover
						link_id = results[i][j].split('=')[0]
						
				#find the rest of the links:
				links = ""
				linkUrl = ""
				#for all links
				for link in range(IDX_RESULTS_OVERALL_INFO+1, len(results[i])):
					linkUrl = ""
					#remove the stuff before the first "="
					tmp2 = results[i][link].split("=")
					linkName = tmp2[0].split("_")[-1]
					del tmp2[0]
					for LinkPart in tmp2:
						linkUrl = linkUrl + "=" + LinkPart
					#clean up the "=" leftover
					linkUrl = linkUrl.strip("=")
					tmp3 = results[i][IDX_RESULTS_OVERALL_INFO].split("=")
					del tmp3[0]
					overallInfo = "=".join(tmp3)

					#determine pattern repository location
					patternRelativePath = results[i][IDX_RESULTS_PATTERN_PATH].replace('/usr/lib/sca/', '')
					patternPackage = ''
					if 'SLE' in patternRelativePath:
						if 'sle15' in patternRelativePath:
							patternPackage = 'sca-patterns-sle15'
						elif 'sle12' in patternRelativePath:
							patternPackage = 'sca-patterns-sle12'
						elif 'sle11' in patternRelativePath:
							patternPackage = 'sca-patterns-sle11'
						elif 'sle10' in patternRelativePath:
							patternPackage = 'sca-patterns-sle10'
						elif 'sle9' in patternRelativePath:
							patternPackage = 'sca-patterns-sle09'
					elif 'OES' in patternRelativePath:
						patternPackage = 'sca-patterns-oes'
					elif 'HAE' in patternRelativePath:
						patternPackage = 'sca-patterns-hae'
					elif 'edirectory' in patternRelativePath:
						patternPackage = 'sca-patterns-edir'
					elif 'filr' in patternRelativePath:
						patternPackage = 'sca-patterns-filr'
					elif 'groupwise' in patternRelativePath:
						patternPackage = 'sca-patterns-groupwise'
					patternSourceURL = 'https://github.com/g23guy/' + patternPackage + '/blob/master/' + patternRelativePath
					
					#put it in html form
					links = links + '<A HREF="' + linkUrl + '" TARGET="_blank">' + linkName + " " + '</A>'
				tmpReturn = tmpReturn + ('<TR STYLE="border:1px solid black; background: #FFFFFF; display:none;" CLASS="'\
					+ Class + \
						'"><TD BGCOLOR="#'\
					+ color +\
						'" WIDTH="2%">&nbsp;</TD><TD BGCOLOR="#EEEEEE" WIDTH="6%">'\
					+ results[i][IDX_RESULTS_CLASS].split("=")[IDX_VALUE] + \
					'</TD><TD BGCOLOR="#EEEEEE" WIDTH="5%">'\
					+ results[i][IDX_RESULTS_CATEGORY].split("=")[IDX_VALUE] + \
					'</TD><TD BGCOLOR="#EEEEEE" WIDTH="5%">'\
					+ results[i][IDX_RESULTS_COMPONENT].split("=")[IDX_VALUE] +\
					'</TD><TD><A HREF="'\
					+ Main_Link + \
					'" TARGET="_blank">'\
					+ overallInfo +\
					'</A>&nbsp;&nbsp;<A ID="PatternLocation" HREF="' + patternSourceURL + '" TARGET="_blank">&nbsp;</A>'\
					+ '</TD><TD WIDTH="8%">'\
					+ links +\
							 '&nbsp;&nbsp;</TD><TD BGCOLOR="#'\
					+ color + \
							 '" WIDTH="2%">&nbsp;</TD></TR>' + "\n")

		#collapse tags
		if numHits > 0:
			tmpReturn = ('<TR STYLE="border:1px solid black;color: #0000FF; background: #FFCC99; font-size:80%; font-weight:normal"><TD BGCOLOR="#'\
			+ color +\
			'" WIDTH="2%">&nbsp;</TD><TD BGCOLOR="#FFCC99" WIDTH="6%"><A ID="NewClass" TITLE="Click to Expand/Collapse" HREF="#" onClick="toggle(\''\
			+ Class +\
			'\');return false;">'\
			+ Class +\
			'</A></TD><TD BGCOLOR="#FFCC99" WIDTH="5%">&nbsp;</TD><TD BGCOLOR="#FFCC99" WIDTH="5%">&nbsp;</TD><TD><A ID="NewClass" TITLE="Click to Expand/Collapse" HREF="#" onClick="toggle(\''\
			+ Class +\
			'\');return false;">'\
			+ str(numHits) + " " + severityTag + Class + " Message(s)" +\
			'</A></TD><TD WIDTH="8%">&nbsp;</TD><TD BGCOLOR="#'\
			+ color +\
			'" WIDTH="2%">&nbsp;</TD></TR>'\
			+ "\n" +tmpReturn)
			returnString = returnString + tmpReturn

	if severityCount > 0:
		if severityCount > 1:
			conditionStr = "Conditions "
		else:
			conditionStr = "Condition "
		tmpReturn = ('<TR STYLE="border:1px solid black;color: #000000; background: #FFCC99; font-size:80%; font-weight:normal"><TD BGCOLOR="#'\
		+ color +\
		'" WIDTH="2%">&nbsp;</TD><TD BGCOLOR="#FFCC99" WIDTH="6%">TOTAL</TD><TD BGCOLOR="#FFCC99" WIDTH="5%">&nbsp;</TD><TD BGCOLOR="#FFCC99" WIDTH="5%">&nbsp;</TD><TD>'\
		+ str(severityCount) +\
		" "\
		+ severityTag +\
		' '\
		+ conditionStr +\
		'Found</TD><TD WIDTH="8%">&nbsp;</TD><TD BGCOLOR="#'\
		+ color +\
		'" WIDTH="2%">&nbsp;</TD></TR>'\
		+ "\n")
		returnString = returnString + tmpReturn

	patternStats[severityIdx] = severityCount

	#well that was fun... return
	return(returnString)

##########################################################################################
# PATTERN ANALYSIS FUNCTIONS
##########################################################################################
# patternLibraryList
##########################################################################################
#lists the patterns available on the system
#prints a list of patterns
def patternLibraryList():
	TOTAL_COUNT=0
	DIRECTORY = {}
	FORMATTING = '{0:>5} : {1}'
	print "Pattern Library Summary\n"
	print FORMATTING.format('Count', 'Pattern Directory')
	print FORMATTING.format('=====','========================================')
	for root, dirs, files in os.walk(SCA_PATTERN_PATH):
#		print "root  = " + str(root)
#		print "dirs  = " + str(dirs)
#		print "files = " + str(files)
#		print
		TOTAL_COUNT += len(files)
		FILES_FOUND = len(files)
		if( FILES_FOUND > 1 ):
			DIRECTORY[root] = FILES_FOUND
		elif( FILES_FOUND > 0 ):
			if( files[0] == "README" ):
				# Readme files don't count
				TOTAL_COUNT -= 1
			else:
				DIRECTORY[root] = FILES_FOUND
		elif( len(dirs) == 0 ):
			DIRECTORY[root] = FILES_FOUND
	for i in sorted(DIRECTORY, key=str.lower):
		print FORMATTING.format(DIRECTORY[i], i)
	print FORMATTING.format(TOTAL_COUNT, 'Total Available Patterns')
	print
	

##########################################################################################
# patternPreProcessor
##########################################################################################
#determines which patterns apply to the supportconfig
#returns a list of applicable patterns
def patternPreProcessor(extractedSupportconfig):
	global verboseMode
	patternFileList = []
	patternDirectories = [SCA_PATTERN_PATH + "/local/"] #always include the local patterns

	#get the total pattern count
	TOTAL_COUNT=0
	for root, dirs, files in os.walk(SCA_PATTERN_PATH):
		TOTAL_COUNT += len(files)
	print "Total Patterns Available:     " + str(TOTAL_COUNT)
	
	#first get the pattern directory paths for all possible valid patterns
	#build directory with SLE and OES versions from basic-environment.txt
	basicEnv = open(extractedSupportconfig + "/basic-environment.txt")
	basicEnvLines = basicEnv.readlines()
	SLE_VERSION = 0
	SLE_SP = 0
	OES_VERSION = 0
	OES_SP = 0
	inOES = False
	notOES = True
	inSLES = False
	inSLESOS = False
	for lineNumber in range(0, len(basicEnvLines)):
		if inSLESOS:
			if "#==[" in basicEnvLines[lineNumber] :
				inSLESOS = False
			elif basicEnvLines[lineNumber].startswith("VERSION_ID"):
				VERSION_ID = basicEnvLines[lineNumber].split("=")[1].strip().strip('"')
				SLE_VERSION = str(VERSION_ID).split(".")[0]
				if( len(str(VERSION_ID).split(".")) > 1 ):
					SLE_SP = VERSION_ID.split(".")[1].strip()
				else:
					SLE_SP = 0
		elif inSLES:
			if "#==[" in basicEnvLines[lineNumber] :
				inSLES = False
			elif basicEnvLines[lineNumber].startswith("VERSION"):
				SLE_VERSION = basicEnvLines[lineNumber].split("=")[1].strip()
			elif basicEnvLines[lineNumber].startswith("PATCHLEVEL"):
				SLE_SP = basicEnvLines[lineNumber].split("=")[1].strip()
		elif inOES:
			if "#==[" in basicEnvLines[lineNumber] :
				inOES = False
			elif "Open Enterprise" in basicEnvLines[lineNumber]:
				notOES = False
			elif basicEnvLines[lineNumber].startswith("VERSION"):
				OES_VERSION = basicEnvLines[lineNumber].split("=")[1].strip().split(".")[0]
			elif basicEnvLines[lineNumber].startswith("PATCHLEVEL"):
				OES_SP = basicEnvLines[lineNumber].split("=")[1].strip()
		elif "# /etc/SuSE-release" in basicEnvLines[lineNumber] :
			inSLES = True
		elif "# /etc/os-release" in basicEnvLines[lineNumber] :
			inSLESOS = True
		elif "# /etc/novell-release" in basicEnvLines[lineNumber] :
			inOES = True
	if notOES:
		OES_VERSION = 0
	if( SLE_VERSION > 0 ):
		patternDirectories.append(str(SCA_PATTERN_PATH) + "/SLE/sle" + str(SLE_VERSION) + "all/")
		patternDirectories.append(str(SCA_PATTERN_PATH) + "/SLE/sle" + str(SLE_VERSION) + "sp" + str(SLE_SP) + "/")
	if( OES_VERSION > 0 ):
		patternDirectories.append(str(SCA_PATTERN_PATH) + "/OES/oes" + str(OES_VERSION) + "all/")
		patternDirectories.append(str(SCA_PATTERN_PATH) + "/OES/oes" + str(OES_VERSION) + "sp" + str(OES_SP) + "/")

	#build directory of additional required patterns by add-on products
	rpmFile = open(extractedSupportconfig + "/rpm.txt")
	RPMs = rpmFile.readlines()
	rpmFile.close()
	inHAE = re.compile('openais|resource-agents|cluster-glue|corosync|csync2|pacemaker|heartbeat', re.IGNORECASE)
	SUMA = re.compile("^susemanager\s|^susemanager-proxy\s", re.IGNORECASE)
	for line in RPMs:
		if inHAE.search(line) and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/HAE/"))
		elif "ndsserv " in line.lower() and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/edirectory/"))
		elif "groupwise" in line.lower() and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/groupwise/"))
		elif "datasync-common " in line.lower() and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/groupwise/"))
		elif "filr-famtd " in line.lower() and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/filr/"))
		elif SUMA.search(line) and not line.startswith("sca-patterns"):
			VER_MAJOR = str(line.split()[-1].split('.')[0])
			VER_MINOR = str(line.split()[-1].split('.')[1])
			patternDirectories.append(str(SCA_PATTERN_PATH + "/suma/suma" + VER_MAJOR + VER_MINOR + "all/"))

	patternDirectories = list(set(patternDirectories)) #create a unique sorted list
	systemDefinition = []
	for systemElement in patternDirectories:
		systemDefinition.append(systemElement.split("/")[-2])
	systemDefinition = sorted(systemDefinition)
	print "Pattern Definition Filter:    " + " ".join(systemDefinition)

	#second build the list of valid patterns from the patternDirectories
	#walk through each valid pattern directory
	for patternDirectory in patternDirectories:
		#only include patterns that exist
		if os.path.isdir(patternDirectory):
			#get the patterns from the valid directory
			for root, dirs, patternFiles in os.walk(patternDirectory):
				#joint the filenames with the root path
				for patternFile in patternFiles:
					patternFileList.append(os.path.join(root, patternFile))

	return patternFileList

##########################################################################################
# emailSCAReport
##########################################################################################
#emails the SCA Report to the specified email address
#this is called by analyze.
#does not return anything
def emailSCAReport(supportconfigFile):
	global htmlOutputFile
	global emailAddrList
	global serverName
	global analysisDateTime
	global patternStats
	timeAnalysis = str(analysisDateTime.year) + "-" + str(analysisDateTime.month).zfill(2) + "-" + str(analysisDateTime.day).zfill(2) + " " + str(analysisDateTime.hour).zfill(2) + ":" + str(analysisDateTime.minute).zfill(2) + ":" + str(analysisDateTime.second).zfill(2)

	if( len(emailAddrList) > 0 ):
		print "Emailing SCA Report To:       " + str(emailAddrList)
#		print "Pattern Stats: " + str(patternStats)
	else:
		return 0
	SERVER = 'localhost'
	TO = re.split(r',\s*|\s*', emailAddrList)
	FROM = 'SCA Tool <root>'
	SUBJECT = "SCA Report for " + str(serverName) + ": " + str(patternStats['Applied']) + "/" + str(patternStats['Total']) + ", " + str(patternStats['Crit']) + ":" + str(patternStats['Warn']) + ":" + str(patternStats['Recc']) + ":" + str(patternStats['Succ'])
	SCA_REPORT = htmlOutputFile.split('/')[-1]

	# create text email
	text = "* Supportconfig Analysis Report *\n"
	text += "Analysis Date:             " + str(timeAnalysis) + "\n"
	text += "Supportconfig Archive:    " + str(supportconfigFile) + "\n"
	text += "Server Analyzed:          " + str(serverName) + "\n"
	text += "Total Patterns Evaluated: " + str(patternStats['Total']) + "\n"
	text += "Applicable to Server:     " + str(patternStats['Applied']) + "\n"
	text += "  Critical:               " + str(patternStats['Crit']) + "\n"
	text += "  Warning:                " + str(patternStats['Warn']) + "\n"
	text += "  Recommended:            " + str(patternStats['Recc']) + "\n"
	text += "  Success:                " + str(patternStats['Succ']) + "\n"
	text += "Source:                   scatool v" + str(SVER) + "\n"

	# create html email
	html = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" '
	html += '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html xmlns="http://www.w3.org/1999/xhtml">\n'
	html += '<body>\n'
	html += '<h1>Supportconfig Analysis Report</h1>\n'
	html += '<table>\n'
	html += "<tr><td>Analysis Date:</td><td>" + str(timeAnalysis) + '</td></tr>\n'
	html += "<tr><td>Supportconfig Archive:</td><td>" + str(supportconfigFile) + '</td></tr>\n'
	html += "<tr><td>Server Analyzed:</td><td>" + str(serverName) + '</td></tr>\n'
	html += "<tr><td>Total Patterns Evaluated:</td><td>" + str(patternStats['Total']) + '</td></tr>\n'
	html += "<tr><td>Applicable to Server:</td><td>" + str(patternStats['Applied']) + '</td></tr>\n'
	html += "<tr><td>&nbsp;&nbsp;Critical:</td><td>" + str(patternStats['Crit']) + '</td></tr>\n'
	html += "<tr><td>&nbsp;&nbsp;Warning:</td><td>" + str(patternStats['Warn']) + '</td></tr>\n'
	html += "<tr><td>&nbsp;&nbsp;Recommended:</td><td>" + str(patternStats['Recc']) + '</td></tr>\n'
	html += "<tr><td>&nbsp;&nbsp;Success:</td><td>" + str(patternStats['Succ']) + '</td></tr>\n'
	html += "<tr><td>Source:</td><td>scatool v" + str(SVER) + '</td></tr>\n'
	html += "</table>\n</body></html>\n\n"
	emailMsg = email.MIMEMultipart.MIMEMultipart('alternative')
	emailMsg['Subject'] = SUBJECT
	emailMsg['From'] = FROM
	emailMsg['To'] = ', '.join(TO)
	emailMsg.attach(email.mime.text.MIMEText(text,'plain'))
	emailMsg.attach(email.mime.text.MIMEText(html,'html'))

	# now attach the file
	fileMsg = email.mime.base.MIMEBase('text','html')
	fileMsg.set_payload(file(htmlOutputFile).read())
	email.encoders.encode_base64(fileMsg)
	fileMsg.add_header('Content-Disposition','attachment;filename=' + SCA_REPORT)
	emailMsg.attach(fileMsg)

	# send email
	server = None
	try:
		server = smtplib.SMTP(SERVER, timeout=15)
		server.sendmail(FROM,TO,emailMsg.as_string())
		return True
	except Exception, error:
		print "  Error: Unable to send email: '%s'." % str(error)
		pass
	finally:
		if server:
			server.quit()
	return False

##########################################################################################
# runPats
##########################################################################################
#run all patterns
#this is called by analyze.
#does not return anything; however, it does set results[]
def runPats(extractedSupportconfig):
	global results
	global patternErrorList
	global patternStats
	global verboseMode
	results = []

	validPatterns = patternPreProcessor(extractedSupportconfig)

	progressBarWidth = 48
	progressCount = 0
	patternCount = 0
	patternStats['Total'] = len(validPatterns)
	patternInterval = ( int(patternStats['Total']) / int(progressBarWidth) )
	if( patternStats['Total'] < progressBarWidth ):
		patternInterval = 1

	print "Total Patterns to Apply:      " + str(patternStats['Total'])
	if verboseMode:
		print "Analyzing Supportconfig:      In Progress"
	else:
		sys.stdout.write("Analyzing Supportconfig:      [%s]" % (" " * progressBarWidth))
		sys.stdout.flush()
		sys.stdout.write("\b" * (progressBarWidth+1)) # return to start of line, after '['
#debug
#		sys.stdout.write("\n")

	for patternFile in validPatterns:
		patternCount += 1
		try:
			p = subprocess.Popen([patternFile, '-p', extractedSupportconfig], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			out, error = p.communicate()
			patternValidated = parseOutput(out, error, patternFile)

			#call parseOutput to see if output was expected
			if verboseMode:
				if patternValidated:
					print " Done:  " + str(patternCount) + " of " + str(patternStats['Total']) + ": " + patternFile
				else:
					print " ERROR: " + str(patternCount) + " of " + str(patternStats['Total']) + ": " + patternErrorList[-1]
			else:
				#advance the progress bar if it's not full yet
#debug
#				sys.stdout.write("Count = " + str(patternCount) + ", Total = " + str(patternStats['Total']) + ", Progress = " + str(progressCount) + ", Width = " + str(progressBarWidth) + ", Interval = " + str(patternInterval) + "\n")
#				sys.stdout.flush()
				if( progressCount < progressBarWidth ):
					#advance the progress bar in equal intervals
					if( patternCount % patternInterval == 0 ):
						progressCount += 1
						sys.stdout.write("=")
						sys.stdout.flush()
		except Exception as e:
			patternErrorList.append(patternFile + " -- Pattern runtime error: " + str(e))
			if verboseMode:
				print " ERROR: " + str(patternCount) + " of " + str(patternStats['Total']) + ": " + patternErrorList[-1]

	#make output look nice
	if not verboseMode:
		while( progressCount < progressBarWidth ):
			progressCount += 1
			sys.stdout.write("=")
			sys.stdout.flush()
	sys.stdout.write("\n")

	patternStats['Applied'] = len(results)
	patternStats['Errors'] = len(patternErrorList)
	print "Applicable Patterns:          " + str(patternStats['Applied'])
	print "Pattern Execution Errors:     " + str(patternStats['Errors'])
	if not verboseMode:
		for patternErrorStr in patternErrorList:
			print "  " + patternErrorStr

##########################################################################################
# parseOutPut
##########################################################################################
#check output. If output is good add it to results, updates patternErrorList with invalid pattern output
def parseOutput(out, error, pat):
	global results
	global patternErrorList
	#if no errors
	if error == "":
		output = out.strip().split("|")
		if( len(output) < len(RESULT_ELEMENT) ):
			patternErrorList.append(pat + " -- Insufficient output elements: " + str(len(output)) + " < " + str(len(RESULT_ELEMENT)))
			return False

		for i in range(0, len(RESULT_ELEMENT)):
			if not RESULT_ELEMENT[i] in output[i]:
				patternErrorList.append(pat + " -- Invalid output element: " + str(RESULT_ELEMENT[i]) + " not found in " + str(output[i]))
				return False

		#if overall outcome of pattern was valid
		if int(output[5].split("=")[1]) >= 0 and int(output[5].split("=")[1]) < 5:
			full = [pat] + output # insert the pattern path at the begining of results
			results.append(full)
		return True
	else:
		patternErrorList.append(pat + " -- Output error: " + str(error.split("\n")[0]))
		return False

##########################################################################################
# doKeepArchive(archive)
##########################################################################################
def doKeepArchive(archive):
	if not archive.endswith('.saved'):
		archiveKeep = archive + ".saved"
		print "Keeping File:                 " + archiveKeep
		shutil.copy2(archive,archiveKeep)

##########################################################################################
# decompressFile(archive, command, options)
##########################################################################################
# decompressFile decompresses the given archive
# Input: archive - path to the supportconfig decompressed tarball
#        command - path to decompression tool
#        options - decompression args
def decompressFile(archive, command, options):
	print "Decompressing File:           " + archive
	process = subprocess.Popen([command, options, archive], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = process.communicate()
	rc = process.returncode
	if( rc > 0 ):
		basecmd = os.path.basename(command)
		print >> sys.stderr, "  Error: Cannot decompress " + basecmd + " file"
		print >> sys.stderr
		sys.exit(5)
	else:
		return True

##########################################################################################
# unTarFile(archive)
##########################################################################################
# Untar a decompress archive
# Input: archive - path to the supportconfig decompressed tarball
def unTarFile(archive):
	print "Extracting Tar File:          " + archive
	process = subprocess.Popen(["/usr/bin/tar", "xf", archive], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = process.communicate()
	rc = process.returncode
	if( rc > 0 ):
		print >> sys.stderr, "  Error: Cannot extract tar file"
		print >> sys.stderr
		sys.exit(6)
	else:
		return True

##########################################################################################
# Core fuctions
##########################################################################################

##########################################################################################
# analyze
##########################################################################################
#analyze server or supportconfig
def analyze(*arg):
	global outputPath
	global htmlOutputFile
	global emailAddrList
	global KeepArchive
	global verboseMode
	global analysisDateTime
	#reset stuff
	dateStamp = analysisDateTime.strftime("%d%m%y")
	timeStamp = str(analysisDateTime.hour).zfill(2) + str(analysisDateTime.minute).zfill(2)
	remoteSupportconfigName = ""
	remoteSupportconfigPath = ""
	extractedSupportconfig = ""
	supportconfigPath = ""
	supportconfigPathTarball = ""
	extractedPath = ""
	deleteArchive = False
	isIP = False
	host = "None"
	isRemoteServer = False
	cleanUp = True
	alloutput = ""
	lineNum = 0
	progressBarWidth = 48
	remoteProgressBarSetup = False
	progressCount = 0
	scHeaderLines = 2
	scTotal = 96 # the number of lines in a standard supportconfig output
	scInterval = int(scTotal / progressBarWidth)

	#if we want to run and analyze a supportconfig
	if len(arg) == 0:
		print "Running Supportconfig On:     localhost"
		scUUID = str(uuid.uuid1())
		supportconfigPath = "/var/log/scc__" + scUUID
		#run supportconfig
		try:
			p = subprocess.Popen(['/sbin/supportconfig', "-bB " + scUUID, "-t /var/log"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			#remove archive
			deleteArchive = True
		#if we cannot run supportconfig
		except Exception:
			print >> sys.stderr, "Error: Cannot run supportconfig."
			print >> sys.stderr
			return
		condition = True

		if verboseMode:
			print "Gathering Supportconfig:      In Progress"
		else:
			sys.stdout.write("Gathering Supportconfig:      [%s]" % (" " * progressBarWidth))
			sys.stdout.flush()
			sys.stdout.write("\b" * (progressBarWidth+1)) # return to start of line, after '['
			sys.stdout.flush()

		#this acts like a do-while. I love do-while :)
		#print output of the subprocess (supportconfig)
		#--DO--
		while condition:
			out = p.stdout.read(1)
			if out != '':
				alloutput = alloutput + out
				if verboseMode:
					sys.stdout.write(out)
					sys.stdout.flush()
				else:
					if out == "\n":
						lineNum += 1
						if ( scHeaderLines > 0 ):
							scHeaderLines -= 1
						else:
							#advance the progress bar if it's not full yet
							if( progressCount < progressBarWidth ):
								#advance the progress bar in equal intervals
								if( lineNum % scInterval == 0 ):
									progressCount += 1
									sys.stdout.write("=")
									sys.stdout.flush()
		#--WHILE--
			condition = not bool(out == "" and p.poll() != None)
			
		if not verboseMode:
			while( progressCount < progressBarWidth ):
				progressCount += 1
				sys.stdout.write("=")
				sys.stdout.flush()
			sys.stdout.write("\n")

	#if a path was given. analyze given file/folder
	elif len(arg) == 1:
		#validate the file/folder/ip given by the end user
		givenSupportconfigPath = arg[0]

		if( givenSupportconfigPath == "." ):
			givenSupportconfigPath = os.getcwd()

		if os.path.isfile(givenSupportconfigPath):
			print "Supportconfig File:           %s" % givenSupportconfigPath
		elif os.path.isdir(givenSupportconfigPath):
			print "Supportconfig Directory:      %s" % givenSupportconfigPath
		else:
			print "Supportconfig Remote Server:  %s" % givenSupportconfigPath
			ping_server = subprocess.Popen(["/bin/ping", "-c1", givenSupportconfigPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			streamdata = ping_server.communicate()[0]
			if ping_server.returncode != 0:
				print >> sys.stderr, "  Error: Cannot communicate with server"
				print >> sys.stderr
				usage()
				return
			else:
				isRemoteServer = True

		#test if we have an IP
		if isRemoteServer:
			try:
				socket.inet_aton(givenSupportconfigPath)
				host = givenSupportconfigPath
				isIP = True
			except socket.error:
				try:
					host = socket.gethostbyname(givenSupportconfigPath.strip("\n"))
					isIP = True
				except:
					if isIP:
						print >> sys.stderr, "  Error: Unable to reach " + givenSupportconfigPath
						return
			if host == "None":
				#Not an IP. Lets hope it is a PATH
				supportconfigPath = givenSupportconfigPath
			else:
				#we have an IP
				print "Running Supportconfig On:     " + givenSupportconfigPath
				sys.stdout.write("  Waiting... ")
				sys.stdout.flush()
				remoteSupportconfigName = str(givenSupportconfigPath) + "_" + str(dateStamp) + "_" + str(timeStamp)
				remoteSupportconfigPath = REMOTE_SC_PATH
				
				#print "lets take a look at that IP "
				try:
					if( len(outputPath) == 0 ):
						outputPath = remoteSupportconfigPath
					#run ssh root@host "supportconfig -R REMOTE_SC_PATH -B <timeStamp>; echo -n \~; cat <path to new supportconfig
					#aka: run supportconfig then send the output back.
					p = subprocess.Popen(['ssh', "root@" + host, 'supportconfig -bR ' + remoteSupportconfigPath + ' -B ' + str(remoteSupportconfigName) + ";echo -n \\~; cat " + remoteSupportconfigPath + "/nts_" + str(remoteSupportconfigName) + ".tbz" + "; rm " + remoteSupportconfigPath + "/nts_" + str(remoteSupportconfigName) + ".tbz*"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
					#create a local verson of the supportconfig output
					localSupportconfig = open(outputPath + "/nts_" + str(remoteSupportconfigName) + ".tbz", 'w')
					#remove local archive
					deleteArchive = True
					condition = True
					endOfSupportconfig = False

					#this acts like a do-while. I love do-while :)
					#print output of the subprocess (the long ssh command)
					#--DO--
					while condition:
						out = p.stdout.read(1)
						#if the end of supportconfig output... start saving output
						if(endOfSupportconfig):
							#save to local supportconfig
							localSupportconfig.write(out)
						elif out != '':
							if ( out == "=" and not remoteProgressBarSetup ):
								remoteProgressBarSetup = True
								if verboseMode:
									print "Gathering Supportconfig:      In Progress"
								else:
									sys.stdout.write("Gathering Supportconfig:      [%s]" % (" " * progressBarWidth))
									sys.stdout.flush()
									sys.stdout.write("\b" * (progressBarWidth+1)) # return to start of line, after '['
									sys.stdout.flush()

							if verboseMode:
								sys.stdout.write(out.strip("~"))
								sys.stdout.flush()
							else:
								if out == "\n":
									lineNum += 1
									if ( scHeaderLines > 0 ):
										scHeaderLines -= 1
									else:
										#advance the progress bar if it's not full yet
										if( progressCount < progressBarWidth ):
											#advance the progress bar in equal intervals
											if( lineNum % scInterval == 0 ):
												progressCount += 1
												sys.stdout.write("=")
												sys.stdout.flush()
						#if we are ate the end of the file output
						if out == "~":
							endOfSupportconfig = True

					#--WHILE--
						condition = not bool(out == "" and p.poll() != None)
					#close the local copy of the remote supportconfig.
					localSupportconfig.close()

					if not verboseMode and remoteProgressBarSetup:
						while( progressCount < progressBarWidth ):
							progressCount += 1
							sys.stdout.write("=")
							sys.stdout.flush()

					supportconfigPath = outputPath + "/nts_" + str(remoteSupportconfigName) + ".tbz"
					fileInfo = os.stat(supportconfigPath)
					if( fileInfo.st_size > 0 ):
						print
						print "Copied Supportconfig:         " + givenSupportconfigPath + " -> localhost"
					else:
						print >> sys.stderr
						print >> sys.stderr, "Error: Failed to copy supportconfig from remote server"
						print >> sys.stderr, "       Verify you can ssh as root into the remote server"
						print >> sys.stderr, "       and manually run supportconfig."
						print >> sys.stderr
						os.remove(supportconfigPath)
						return
				except Exception:
					print >> sys.stderr
					print >> sys.stderr, "  Error: Supportconfig execution failed on " + givenSupportconfigPath + "."
					return
		else:
			supportconfigPath = givenSupportconfigPath
	else:
		#too many arguments
		print >> sys.stderr, "Please run: \"help analyze\""

	OS_PATH = os.environ["PWD"]
	if( len(OS_PATH) > 0 ):
		OS_PATH += "/"
	else:
		OS_PATH = "./"
	if supportconfigPath.startswith("./"):
		supportconfigPath = re.sub("^./", OS_PATH, supportconfigPath)
	elif not supportconfigPath.startswith("/"):
		supportconfigPath = OS_PATH + supportconfigPath
	base = os.path.splitext(supportconfigPath)[0]
	if base.endswith('.tar'):
		supportconfigPathTarball = base
		extractedSupportconfig = os.path.splitext(base)[0]
	else:
		supportconfigPathTarball = base + '.tar'
		extractedSupportconfig = base
#	print
#	print " + Base =                   " + base
#	print " + extractedSupportconfig = " + extractedSupportconfig
#	print
	htmlOutputFile = extractedSupportconfig + "_report.html"

	#if given a supportconfig archive
	if os.path.isfile(supportconfigPath):
		print "Evaluating File:              " + supportconfigPath
		#extract file
		#set TarFile and find the path of the soon to be extracted supportconfig
		fileInfo = os.stat(supportconfigPath)
		if( fileInfo.st_size > 0 ):
			process = subprocess.Popen(["/usr/bin/file", "--brief", "--mime-type", supportconfigPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = process.communicate()
#			print "Detected File Type:           " + stdout
			if re.search("/x-xz", stdout):
				if supportconfigPath.endswith('.txz'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/xz', '-d')
					unTarFile(supportconfigPathTarball)
				elif supportconfigPath.endswith('.tar.xz'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/xz', '-d')
					unTarFile(supportconfigPathTarball)
				else:
					print >> sys.stderr, "Error: Unknown xz extension"
					print >> sys.stderr
					return
			elif re.search("/x-bzip2", stdout):
				if supportconfigPath.endswith('.tbz'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/bzip2', '-d')
					unTarFile(supportconfigPathTarball)
				elif supportconfigPath.endswith('.tar.bz'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/bzip2', '-d')
					unTarFile(supportconfigPathTarball)
				elif supportconfigPath.endswith('.tbz2'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/bzip2', '-d')
					unTarFile(supportconfigPathTarball)
				elif supportconfigPath.endswith('.tar.bz2'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/bzip2', '-d')
					unTarFile(supportconfigPathTarball)
				else:
					print >> sys.stderr, "Error: Unknown bzip2 extension"
					print >> sys.stderr
					return
			elif re.search("/x-gzip", stdout):
				if supportconfigPath.endswith('.tgz'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/gzip', '-df')
					unTarFile(supportconfigPathTarball)
				elif supportconfigPath.endswith('.tar.gz'):
					KeepArchive and doKeepArchive(supportconfigPath)
					decompressFile(supportconfigPath, '/usr/bin/gzip', '-df')
					unTarFile(supportconfigPathTarball)
				else:
					print >> sys.stderr, "Error: Unknown gzip extension"
					print >> sys.stderr
					return
			elif re.search("/x-tar", stdout):
				KeepArchive and doKeepArchive(supportconfigPath)
				print "Extracting Tar File:          " + supportconfigPath
				process = subprocess.Popen(["/usr/bin/tar", "xf", supportconfigPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				stdout, stderr = process.communicate()
				rc = process.returncode
			else:
				print >> sys.stderr, "  Warning: Unknown supportconfig archive format"
				print >> sys.stderr
				return
		else:
			print >> sys.stderr, "  Error: Zero byte file: " + supportconfigPath
			print >> sys.stderr
			return
		deleteArchive = True

	#if given an extracted supportconfig
	elif os.path.isdir(supportconfigPath):
		extractedSupportconfig = supportconfigPath
		if( len(outputPath) > 0 ):
			htmlOutputFile = outputPath + "/" + extractedSupportconfig.strip("/").split("/")[-1] + "_report.html"
		else:
			htmlOutputFile = extractedSupportconfig
			if htmlOutputFile.endswith("/"):
				htmlOutputFile = htmlOutputFile[:-1]
			tmp = htmlOutputFile.split("/")
			del tmp[-1]
			htmlOutputFile = "/".join(tmp) + "/" + extractedSupportconfig.strip("/").split("/")[-1] + "_report.html"
		#we don't want to delete something we did not create.
		cleanUp = False

        extractedSupportconfig = extractedSupportconfig + "/"
	print "Processing Directory:         " + extractedSupportconfig
	#check for required supportconfig files...
	testFile = "basic-environment.txt"
	if not os.path.isfile(extractedSupportconfig + testFile):
		#not a supportconfig. quit out
		print >> sys.stderr, "  Error:   Invalid supportconfig archive - missing " + testFile
		print >> sys.stderr
		return

	testFile = "rpm.txt"
	if not os.path.isfile(extractedSupportconfig + testFile):
		#not a supportconfig. quit out
		print >> sys.stderr, "  Error:   Invalid supportconfig archive - missing " + testFile
		print >> sys.stderr
		return
	
	#At this point we should have a extracted supportconfig 
	#run patterns on supportconfig
	runPats(extractedSupportconfig)
	getHtml(htmlOutputFile, extractedSupportconfig, supportconfigPath.split("/")[-1])
	print ("SCA Report File:              %s" % htmlOutputFile)

	emailSCAReport(supportconfigPath)

	#clean up
#	print " + supportconfigPathTarball = " + supportconfigPathTarball
#	print " + supportconfigPath = " + supportconfigPath
	if cleanUp:
		shutil.rmtree(extractedSupportconfig)
	if deleteArchive:
		if os.path.isfile(supportconfigPath):
			os.remove(supportconfigPath)
		if os.path.isfile(supportconfigPathTarball):
			os.remove(supportconfigPathTarball)
		if os.path.isfile(supportconfigPath + ".md5"):
			os.remove(supportconfigPath + ".md5")
	print
			
##########################################################################################
# help
##########################################################################################
def help(*arg):
	#help run without any command name given. print available commands (if a help page is available for a command print first line of help page)
	if len(arg) == 0:
		printed = False
		print "Available Commands:\n"
		for i in range(0, len(COMMANDS)):
			printed = False
			for e in COMMANDS_HELP:
				if e.startswith(COMMANDS[i]):
					print e.split("\n")[0]
					printed = True
					break
			if not printed:
				print COMMANDS[i]
		print "\nRun \"help <command name>\" for more help\n"
		
	#help was run with a command given
	if len(arg) == 1:
		#if valid command was given
		if arg[0] in COMMANDS:
			#find the help page
			for i in COMMANDS_HELP:
				if i.split(":")[0] == arg[0]:
					#print i (without the command name)
					print "\n" + i[len(arg[0])+2:] + "\n"
					return
			print >> sys.stderr, "Error: No help page for command \"" + arg[0] + "\""
		else:
			print >> sys.stderr, "Error: " + arg[0] + " is not a command"

##########################################################################################
# view
##########################################################################################
#take a look at the html
#once analyze is run you can use "view" to look at the data
#use: "view" or "view <path to html>"
def view(*arg):
	global htmlOutputFile
	#if no path given. try to view the global html output file.
	if len(arg) == 0:
		try:
			
			#check path and see if output file is set
			if htmlOutputFile == "":
				print >> sys.stderr, "Error: Cannot open output file. Have you run analyze yet?"
				return
			if os.path.isfile(htmlOutputFile):
				#check that this is html
				if htmlOutputFile.endswith(".htm") or htmlOutputFile.endswith(".html"):
					os.system("w3m " + htmlOutputFile)
				else:
					print >> sys.stderr, htmlOutputFile + " is not a html file"
			else:
				print >> sys.stderr, htmlOutputFile + " is not a file."
		except Exception:
			print >> sys.stderr, "Error: Cannot open output file. Have you run analyze yet?"
			
	#A path was given
	elif len(arg) == 1:
		try:
			#check the path
			if os.path.isfile(arg[0]):
				#check that this is html
				if arg[0].endswith(".htm") or arg[0].endswith(".html"):
					os.system("w3m " + arg[0])
				else:
					print >> sys.stderr, arg[0] + " is not a html file"
			else:
				print >> sys.stderr, arg[0] + " is not a file."
		except Exception:
			pass
		
	#....More then two arguments given. Nice :)
	else:
		print >> sys.stderr, "Please run \"help view\""

##########################################################################################
# main
##########################################################################################
#read in arguments
analyzeServer = False
analyzeFile = ""

# Process command line arguments
if( len(sys.argv[1:]) > 0 ):
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ha:so:kcvpe:")
	except getopt.GetoptError as err:
		# print help information and exit:
		print "Error: " + str(err) # will print something like "option -b not recognized"
		print
		usage()
		sys.exit(2)

	analyzeServer = False
	analyzeFile = ""
	for startUpOption, startUpOptionValue in opts:
		if startUpOption == "-h":
			usage()
			sys.exit()
		elif startUpOption in ("-p"):
			patternLibraryList()
			sys.exit()
		elif startUpOption in ("-k"):
			KeepArchive = True
		elif startUpOption in ("-e"):
			emailAddrList = startUpOptionValue
		elif startUpOption in ("-s"):
			analyzeServer = True
		elif startUpOption in ("-v"):
			verboseMode = True
		elif startUpOption in ("-a"):
			analyzeServer = True
			analyzeFile = startUpOptionValue
		elif startUpOption in ("-o"):
			outputPath = startUpOptionValue
		else:
			assert False, "Invalid option"
else:
	usage()
	sys.exit()

if( len(opts) == 0 and len(args) > 0 ):
	analyzeServer = True
	analyzeFile = args[0]
elif not analyzeServer:
	print "Error: No server to analyze, use -s or -a."
	print
	usage()
	sys.exit()

#validate outputPath
if( len(outputPath) > 0 ):
	if os.path.isdir(outputPath):
		#clean trailing "/"
		if outputPath.endswith("/"):
			outputPath = outputPath[:-1]
	else:
		print "Error: Directory not found -- " + outputPath
		print
		print "Use -o path to specify a valid directory"
		print
		usage()
		sys.exit(2)

#if autoExit and analyzeServer:
if analyzeServer == True and analyzeFile != "":
	analyze(analyzeFile)
elif analyzeServer == True and analyzeFile == "":
	analyze()

