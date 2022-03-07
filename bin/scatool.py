##############################################################################
# scatool.py - Supportconfig Analysis (SCA) Tool
# Copyright (c) 2014-2022 SUSE LLC
#
# Description:  Runs and analyzes local or remote supportconfigs
# Modified:     2022 Mar 07

##############################################################################
#command
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
#     Jason Record <jason.record@suse.com>
#
##############################################################################
SVER = '1.5.1-1'

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
# Global Declarations
##########################################################################################
global loglevel
global results
global patternErrorList
global knownClasses
global HTML
global outputPath
global htmlOutputFile
global emailAddrList
global removeArchive
global analysisDateTime
global patternStats
global patternDict
global firstSize
global fieldOutput
global progressBarWidth
global productsList
global distroInfo
loglevel = {'current': 1, 'quiet': 0, 'normal': 1, 'verbose': 2, 'debug': 3}

##########################################################################################
# HELP FUNCTIONS
##########################################################################################
def title():
	print("#####################################################################################")
	print("#   SCA Tool v" + SVER)
	print("#####################################################################################")
	print()

def usage():
	print("Usage: scatool [OPTIONS] <archive|server>")
	print()
	print("OPTIONS")
	print(" -h       Displays this screen")
	print(" -s       Analyze the local server")
	print(" -o path  HTML report output directory (OUTPUT_PATH)")
	print(" -e list  Send HTML report to email address(es) provided. Comma separated list")
	print(" -r       Remove archive files (REMOVE_ARCHIVE) leaving only the report html file")
	print(" -p       Print a pattern summary")
	print(" -q       Quiet output")
	print(" -v       Verbose output")
	print()


##########################################################################################
# Environment and Global Variables
##########################################################################################
#setup environment and PWD
try:
	os.chdir(os.environ["PWD"])
	setup = os.environ["SCA_READY"]
except Exception:
	title()
	print("Error: Do not run directly; use scatool", file=sys.stderr)
	print(file=sys.stderr)
	usage()
	sys.exit()
if not setup:
	title()
	usage()
	print(file=sys.stderr)
	sys.exit()


try:
	SCA_PATTERN_PATH = str(os.environ["SCA_PATTERN_PATH"])
except Exception:
	SCA_PATTERN_PATH = "/usr/lib/sca/patterns"

try:
	REMOVE_ARCHIVE = int(os.environ["REMOVE_ARCHIVE"])
except Exception:
	REMOVE_ARCHIVE = 0

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
	LOGLEVEL = int(os.environ["LOGLEVEL"])
	if( LOGLEVEL > loglevel['debug'] ):
		loglevel['current'] = loglevel['debug']
	elif( LOGLEVEL < loglevel['quiet'] ):
		loglevel['current'] = loglevel['quiet']
	else:
		loglevel['current'] = loglevel['normal']
except Exception:
	loglevel['current'] = loglevel['normal']

firstSize = 30
fieldOutput = "{0:" + str(firstSize) + "} {1}"
progressBarWidth = 52
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

if( REMOVE_ARCHIVE > 0 ):
	removeArchive = True
else:
	removeArchive = False

if( len(OUTPUT_PATH) > 0 ):
	outputPath = OUTPUT_PATH
else:
	outputPath = ""

if( len(OUTPUT_EMAIL_LIST) > 0 ):
	emailAddrList = OUTPUT_EMAIL_LIST
else:
	emailAddrList = ""

analysisDateTime = datetime.datetime.now()

#order dependent list of pattern output elements
RESULT_ELEMENT = ["META_CLASS", "META_CATEGORY", "META_COMPONENT", "PATTERN_ID", "PRIMARY_LINK", "OVERALL", "OVERALL_INFO", "META_LINK_"]

productsList = []
distroInfo = {'serverName': 'Unknown', 'hardWare': 'Unknown', 'virtualization': 'None'}

##########################################################################################
# getProductsList(extractedSupportconfig)
##########################################################################################
def getProductsList(*arg):
	global productsList
	global distroInfo
	global analysisDateTime

	distroInfo['timeAnalysis'] = str(analysisDateTime.year) + "-" + str(analysisDateTime.month).zfill(2) + "-" + str(analysisDateTime.day).zfill(2) + " " + str(analysisDateTime.hour).zfill(2) + ":" + str(analysisDateTime.minute).zfill(2) + ":" + str(analysisDateTime.second).zfill(2)
	distroInfo['timeArchiveRun'] = "0000-00-00 00:00:00"
	distroInfo['Summary'] = ''

	#load basic-environment.txt
	try:
		with open(arg[0] + "/basic-environment.txt") as f:
			BASIC_ENV = f.read().splitlines()
	except:
		BASIC_ENV = []

	productInfo = {'tag': 'sle', 'patternTag': 'SLE', 'nameTag': 'Distribution:', 'name': '', 'versionTag': 'Service Pack:', 'version': '', 'vermajor': '', 'verminor': ''}

	#read basic-environment line by line to pull out data.
	IN_DATE = False
	IN_UNAME = False
	IN_OS_RELEASE = False
	IN_SUSE_RELEASE = False
	for line in BASIC_ENV:
		if "Script Version:" in line:
			distroInfo['supportconfigVersion'] = line.split(':')[-1].strip()
		elif line.startswith("Hardware:"):
			distroInfo['hardWare'] = line.split(":")[1].strip()
		elif line.startswith("Hypervisor:"):
			distroInfo['virtualization'] = line.split(":")[1].strip()
		elif line.startswith("Identity:"):
			distroInfo['vmIdentity'] = line.split(":")[1].strip()
		elif "/bin/date" in line:
			IN_DATE = True
		elif "/bin/uname -a" in line:
			IN_UNAME = True
		elif "/etc/os-release" in line:
			IN_OS_RELEASE = True
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
					distroInfo['timeArchiveRun'] = tmp[-1].strip() + "-" + tmpMonth + "-" + tmp[2].strip().zfill(2) + " " + tmp[3].strip()
					IN_DATE = False
		elif( IN_UNAME ):
			if "#==[" in line:
				IN_UNAME = False
			else:
				tmp = line.split()
				if( len(tmp) >= 3 ):
					distroInfo['kernelVersion'] = tmp[2].strip()
					distroInfo['serverName'] = tmp[1].strip()
					distroInfo['osArch'] = tmp[-2].strip()
					IN_UNAME = False
		elif( IN_OS_RELEASE ):
			if "#==[" in line:
				IN_OS_RELEASE = False
				productInfo['name'] = str(distroInfo['Summary']) + " (" + distroInfo['osArch'] + ")"
			else:
				if line.lower().startswith("pretty_name"):
					distroInfo['Summary'] = line.split('=')[-1].replace('"', '').strip()
				elif line.lower().startswith("version_id"):
					VERSION_ID_INFO = line.replace('"', "").strip().split('=')[1].split('.')
					productInfo['vermajor'] = str(VERSION_ID_INFO[0])
					if( len(VERSION_ID_INFO) > 1 ):
						productInfo['verminor'] = str(VERSION_ID_INFO[1])
					else:
						productInfo['verminor'] = "0"
					productInfo['version'] = productInfo['verminor']

	# Look for SUSE release as a last resort
	if( len(distroInfo['Summary']) == 0 ):
		for line in BASIC_ENV:
			if "/etc/SuSE-release" in line:
				IN_SUSE_RELEASE = True
			elif( IN_SUSE_RELEASE ):
				if "#==[" in line:
					IN_SUSE_RELEASE = False
					productInfo['name'] = str(distroInfo['Summary'])
				else:
					if( len(distroInfo['Summary']) > 0 ):
						if line.lower().startswith("version"):
							productInfo['vermajor'] = line.split('=')[-1].replace('"', '').strip()
						elif line.lower().startswith("patchlevel"):
							productInfo['verminor'] = line.split('=')[-1].replace('"', '').strip()
						productInfo['version'] = productInfo['verminor']
					else:
						distroInfo['Summary'] = line.strip()

	productsList.append(productInfo)

	del BASIC_ENV


	#load summary.xml
	try:
		with open(arg[0] + "/summary.xml") as f:
			SUMMARY = f.read().splitlines()
			f.close()
	except:
		SUMMARY = []

	PROD_START = re.compile(r'<product\s|<product>', re.IGNORECASE)
	PROD_END = re.compile(r'</product>', re.IGNORECASE)
	IN_PRODUCT = False

	#detect SLE for VMWARE
	PROD_NAME = re.compile(r'<summary>SUSE Linux Enterprise Server .* for VMware</summary>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'tag': 'vmw', 'patternTag': 'VMware', 'nameTag': 'Product:', 'name': '', 'versionTag': 'Version:', 'version': '', 'vermajor': '', 'verminor': ''}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['name'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['version'] = re.search(r'>(.+?)<', LINE).group(1)
					if( "." in INFO['version'] ):
						(INFO['vermajor'], INFO['verminor']) = INFO['version'].split(".")
					else:
						INFO['vermajor'] = INFO['version']
						INFO['verminor'] = "0"
				except:
					True
			if( INFO['name'] and INFO['version'] ):
				IN_PRODUCT = False
				productsList.append(INFO)
				break
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	#detect SLE for SAP
	PROD_NAME = re.compile(r'<summary>SUSE LINUX Enterprise Server for SAP Applications.*</summary>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'tag': 'sap', 'patternTag': 'SAP', 'nameTag': 'Product:', 'name': '', 'versionTag': 'Version:', 'version': '', 'vermajor': '', 'verminor': ''}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['name'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['version'] = re.search(r'>(.+?)<', LINE).group(1)
					if( "." in INFO['version'] ):
						(INFO['vermajor'], INFO['verminor']) = INFO['version'].split(".")
					else:
						INFO['vermajor'] = INFO['version']
						INFO['verminor'] = "0"
				except:
					True
			if( INFO['name'] and INFO['version'] ):
				IN_PRODUCT = False
				productsList.append(INFO)
				break
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	#get HAE information
	PROD_NAME = re.compile(r'<summary>SUSE Linux Enterprise High Availability Extension.*</summary>', re.IGNORECASE)
	PROD_VER = re.compile(r'<version>.*</version>', re.IGNORECASE)
	INFO = {'tag': 'hae', 'patternTag': 'HAE', 'nameTag': 'Product:', 'name': '', 'versionTag': 'Version:', 'version': '', 'vermajor': '', 'verminor': ''}
	for LINE in SUMMARY:
		if( IN_PRODUCT ):
			if PROD_END.search(LINE):
				IN_PRODUCT = False
			elif PROD_NAME.search(LINE):
				try:
					INFO['name'] = re.search(r'>(.+?)<', LINE).group(1).replace('-', ' ')
				except:
					True
			elif PROD_VER.search(LINE):
				try:
					INFO['version'] = re.search(r'>(.+?)<', LINE).group(1)
					if( "." in INFO['version'] ):
						(INFO['vermajor'], INFO['verminor']) = INFO['version'].split(".")
					else:
						INFO['vermajor'] = INFO['version']
						INFO['verminor'] = "0"
				except:
					True
			if( INFO['name'] and INFO['version'] ):
				IN_PRODUCT = False
				productsList.append(INFO)
				break
		elif PROD_START.search(LINE):
			IN_PRODUCT = True

	#get SUSE Manager information
	# TO DO

	del SUMMARY

#	print()
#	print(distroInfo)
#	print()
#	print("[")
#	for INFO in productsList:
#		print(str(INFO))
#	print("]")
#	sys.exit()


##########################################################################################
# HTML REPORT FUNCTIONS
##########################################################################################
##########################################################################################
# getHeader
##########################################################################################
#returns html code. This is the part about the server.

def getHeader(*arg):
#%%% No *arg needed??
	global productsList
	global distroInfo
	#reset variables
	returnHTML = ""

	#set archive name if given
	if len(arg) == 1:
		arcName = arg[0]
	else:
		arcName = ""

	#create HTML from the data we just got
	returnHTML += '<H1>Supportconfig Analysis Report</H1>\n'
	returnHTML += '<H2><HR />Server Information</H2>\n'

	returnHTML += '<TABLE CELLPADDING="5">\n'
	returnHTML += '<TR><TD><B>Analysis Date:</B></TD><TD>'
	returnHTML += distroInfo['timeAnalysis']
	returnHTML += '</TD></TR>\n'
	returnHTML += '<TR><TD><B>Supportconfig Run Date:</B></TD><TD>'
	returnHTML += distroInfo['timeArchiveRun']
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
	returnHTML += distroInfo['serverName']
	returnHTML += '</TD><TD><B>Hardware:</B></TD><TD>'
	returnHTML += distroInfo['hardWare']
	returnHTML += '</TD></TR>\n'

	#Products included in supportconfig
	for PROD in productsList:
		returnHTML += '<TR><TD><B>'
		returnHTML += str(PROD['nameTag'])
		returnHTML += '</B></TD><TD>'
		returnHTML += str(PROD['name'])
		returnHTML += '</TD><TD><B>'
		returnHTML += str(PROD['versionTag'])
		returnHTML += '</B></TD><TD>'
		returnHTML += str(PROD['version'])
		returnHTML += '</TD></TR>\n'

	if distroInfo['virtualization'] != "None" and distroInfo['virtualization'] != "":
		#hypervisor stuff
		returnHTML += '<TR><TD><B>Hypervisor:</B></TD><TD>'
		returnHTML += distroInfo['virtualization']
		returnHTML += '</TD><TD><B>Identity:</B></TD><TD>'
		returnHTML += distroInfo['vmIdentity']
		returnHTML += '</TD></TR>\n'

	#kernel Version and Supportconfig version
	returnHTML += '<TR><TD><B>Kernel Version:</B></TD><TD>'
	returnHTML += distroInfo['kernelVersion']
	returnHTML += '</TD><TD><B>Supportconfig Version:</B></TD><TD>'
	returnHTML += distroInfo['supportconfigVersion']
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
	global distroInfo
	
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
	HTML += getHeader(OutPutFile)

	# getHeader probes the archive for distroInfo['serverName'], so the header has to be retrieved after getHeader is called.
	# temporarily storing header in HTML_HEADER
	#html top bit:
	HTML_HEADER += "<!DOCTYPE html>" + "\n"
	HTML_HEADER += "<HTML>" + "\n"
	HTML_HEADER += "<HEAD>" + "\n"
	HTML_HEADER += "<TITLE>SCA Report for " + distroInfo['serverName'] + "</TITLE>" + "\n"
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
					elif 'HAE' in patternRelativePath:
						patternPackage = 'sca-patterns-hae'
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
	print("Pattern Library Summary\n")
	print(FORMATTING.format('Count', 'Pattern Directory'))
	print(FORMATTING.format('=====','========================================'))
	for root, dirs, files in os.walk(SCA_PATTERN_PATH):
#		print "root  = " + str(root)
#		print "dirs  = " + str(dirs)
#		print "files = " + str(files)
#		print
		TOTAL_COUNT += len(files)
		FILES_FOUND = len(files)
		if( FILES_FOUND > 1 ):
			DIRECTORY[root] = FILES_FOUND
			for onefile in files:
				if( onefile == "README" ):
					TOTAL_COUNT -= 1
					break
		elif( FILES_FOUND > 0 ):
			if( files[0] == "README" ):
				# Readme files don't count
				TOTAL_COUNT -= 1
			else:
				DIRECTORY[root] = FILES_FOUND
		elif( len(dirs) == 0 ):
			DIRECTORY[root] = FILES_FOUND
	for i in sorted(DIRECTORY, key=str.lower):
		print(FORMATTING.format(DIRECTORY[i], i))
	print(FORMATTING.format(TOTAL_COUNT, 'Total Available Patterns'))
	print()


##########################################################################################
# patternPreProcessor
##########################################################################################
#determines which patterns apply to the supportconfig
#returns a list of applicable patterns
def patternPreProcessor(extractedSupportconfig):
	global loglevel
	global fieldOutput
	global productsList
	getProductsList(extractedSupportconfig)
	patternFileList = []
	patternDirectories = [SCA_PATTERN_PATH + "/local/"] #always include the local patterns

	#get the total pattern count
	TOTAL_COUNT=0
	for root, dirs, files in os.walk(SCA_PATTERN_PATH):
		TOTAL_COUNT += len(files)
	if( loglevel['current'] >= loglevel['normal'] ):
		print(fieldOutput.format('Total Patterns Available:', TOTAL_COUNT))

	for CLASS in productsList:
		basePatternPath = str(SCA_PATTERN_PATH) + "/" + str(CLASS['patternTag']) + "/"
		classPath = basePatternPath + str(CLASS['tag']) + str(CLASS['vermajor']) + "all/"
		if os.path.isdir(classPath):
			patternDirectories.append(classPath)
		classPath = basePatternPath + str(CLASS['tag']) + str(CLASS['vermajor']) + "sp" + str(CLASS['verminor']) + "/"
		if os.path.isdir(classPath):
			patternDirectories.append(classPath)

	patternDirectories = list(set(patternDirectories)) #create a unique sorted list
	systemDefinition = []
	for systemElement in patternDirectories:
		systemDefinition.append(systemElement.split("/")[-2])
	systemDefinition = sorted(systemDefinition)
	if( loglevel['current'] >= loglevel['normal'] ):
		print(fieldOutput.format('Pattern Definition Filter:', ' '.join(systemDefinition)))

	#second build the list of valid patterns from the patternDirectories
	#walk through each valid pattern directory
	for patternDirectory in patternDirectories:
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
	global loglevel
	global htmlOutputFile
	global emailAddrList
	global distroInfo
	global analysisDateTime
	global patternStats
	global fieldOutput
	timeAnalysis = str(analysisDateTime.year) + "-" + str(analysisDateTime.month).zfill(2) + "-" + str(analysisDateTime.day).zfill(2) + " " + str(analysisDateTime.hour).zfill(2) + ":" + str(analysisDateTime.minute).zfill(2) + ":" + str(analysisDateTime.second).zfill(2)

	if( len(emailAddrList) > 0 ):
		if( loglevel['current'] >= loglevel['normal'] ):
			print(fieldOutput.format('Emailing SCA Report To:', emailAddrList))
		if( loglevel['current'] >= loglevel['debug'] ):
			print(fieldOutput.format('+ Pattern Stats', patternStats))
	else:
		return 0
	SERVER = 'localhost'
	TO = re.split(r',\s*|\s*', emailAddrList)
	FROM = 'SCA Tool <root>'
	SUBJECT = "SCA Report for " + str(distroInfo['serverName']) + ": " + str(patternStats['Applied']) + "/" + str(patternStats['Total']) + ", " + str(patternStats['Crit']) + ":" + str(patternStats['Warn']) + ":" + str(patternStats['Recc']) + ":" + str(patternStats['Succ'])
	SCA_REPORT = htmlOutputFile.split('/')[-1]

	# create text email
	text = "* Supportconfig Analysis Report *\n"
	text += "Analysis Date:             " + str(timeAnalysis) + "\n"
	text += "Supportconfig Archive:    " + str(supportconfigFile) + "\n"
	text += "Server Analyzed:          " + str(distroInfo['serverName']) + "\n"
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
	html += "<tr><td>Server Analyzed:</td><td>" + str(distroInfo['serverName']) + '</td></tr>\n'
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
	except Exception as error:
		print("  Error: Unable to send email: '%s'." % str(error), file=sys.stderr)
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
	global loglevel
	global fieldOutput
	global progressBarWidth
	results = []

	validPatterns = patternPreProcessor(extractedSupportconfig)

	progressCount = 0
	patternCount = 0
	patternStats['Total'] = len(validPatterns)
	verboseLine = '{0:6} {1:>5} of {2} {3}'
	patternInterval = int( int(patternStats['Total']) / int(progressBarWidth) )
	if( patternStats['Total'] < progressBarWidth ):
		patternInterval = 1
	patternSkipped = False

	if( loglevel['current'] >= loglevel['normal'] ):
		print(fieldOutput.format('Total Patterns to Apply:', patternStats['Total']))

	if( loglevel['current'] >= loglevel['verbose'] ):
		print(fieldOutput.format('Analyzing Supportconfig:', 'In Progress'))
	elif( loglevel['current'] == loglevel['normal'] ):
		sys.stdout.write("Analyzing Supportconfig:       [%s]" % (" " * progressBarWidth))
		sys.stdout.flush()
		sys.stdout.write("\b" * (progressBarWidth+1)) # return to start of line, after '['
#		sys.stdout.write("\n")

	for patternFile in validPatterns:
		patternCount += 1
		try:
			if patternFile.endswith("README"):
				patternSkipped = True
			else:
				cmd = patternFile + " -p " + extractedSupportconfig
				if( loglevel['current'] >= loglevel['debug'] ):
					print(fieldOutput.format('+ Process Command', cmd))
				p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
				out, error = p.communicate()
				patternValidated = parseOutput(out, error, patternFile)

			#call parseOutput to see if output was expected
			if( loglevel['current'] >= loglevel['verbose'] ):
				if patternSkipped:
					print(verboseLine.format('Skip:', patternCount, patternStats['Total'], patternFile))
					patternSkipped = False
				else:
					if patternValidated:
						print(verboseLine.format('Done:', patternCount, patternStats['Total'], patternFile))
						#print(" Done:  " + str(patternCount) + " of " + str(patternStats['Total']) + ": " + patternFile)
					else:
						print(verboseLine.format('ERROR:', patternCount, patternStats['Total'], patternErrorList[-1]))
			elif( loglevel['current'] == loglevel['normal'] ):
				#advance the progress bar if it's not full yet
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
			if( loglevel['current'] >= loglevel['verbose'] ):
				print(verboseLine.format('ERROR:', patternCount, patternStats['Total'], patternErrorList[-1]))

	#make output look nice
	if( loglevel['current'] == loglevel['normal'] ):
		while( progressCount < progressBarWidth ):
			progressCount += 1
			sys.stdout.write("=")
			sys.stdout.flush()
		sys.stdout.write("\n")

	patternStats['Applied'] = len(results)
	patternStats['Errors'] = len(patternErrorList)
	if( loglevel['current'] >= loglevel['normal'] ):
		print(fieldOutput.format('Applicable Patterns:', patternStats['Applied']))
		print(fieldOutput.format('Pattern Execution Errors:', patternStats['Errors']))
	if( loglevel['current'] == loglevel['normal'] ):
		for patternErrorStr in patternErrorList:
			print("  " + patternErrorStr)

##########################################################################################
# parseOutPut
##########################################################################################
#check output. If output is good add it to results, updates patternErrorList with invalid pattern output
def parseOutput(out, error, pat):
	global results
	global loglevel
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
		if( loglevel['current'] >= loglevel['debug'] ):
			patternErrorList.append(pat + " -- Output error: " + str(error))
		else:
			patternErrorList.append(pat + " -- Output error: " + str(error.split("\n")[0]))
		return False

##########################################################################################
# extractFile(archive, options)
##########################################################################################
# extractFile extracts the archive with tar
# Input: archive - path to the supportconfig decompressed tarball
#        options - tar extraction args
def extractFile(archive, options):
	global loglevel
	global fieldOutput
	if( loglevel['current'] >= loglevel['normal'] ):
		print(fieldOutput.format('Extracting File:', archive))
	archdir = os.path.dirname(archive)
	cmd = "tar -v " + options + " "  + archive + " -C " + archdir
	if( loglevel['current'] >= loglevel['debug'] ):
		print(fieldOutput.format('+ Process Command', cmd))
	process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
	stdout, stderr = process.communicate()
	outfile = stdout.splitlines()[0]
	pathInTarball = archdir + '/' + os.path.dirname(outfile)
	if( loglevel['current'] >= loglevel['debug'] ):
		print(fieldOutput.format('+ Embedded Directory', pathInTarball))
	rc = process.returncode
	if( rc > 0 ):
		print("+ Error: Cannot extract tar file", file=sys.stderr)
		print(stderr, file=sys.stderr)
		print(file=sys.stderr)
		sys.exit(7)
	else:
		return pathInTarball

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
	global removeArchive
	global loglevel
	global analysisDateTime
	global fieldOutput
	global progressBarWidth

	#reset stuff
	dateStamp = analysisDateTime.strftime("%y%m%d")
	timeStamp = str(analysisDateTime.hour).zfill(2) + str(analysisDateTime.minute).zfill(2) + str(analysisDateTime.second).zfill(2)
	remoteSupportconfigName = ""
	remoteSupportconfigPath = ""
	extractedSupportconfig = ""
	supportconfigPath = ""
	extractedPath = ""
	extractedEmeddedPath = ""
	isIP = False
	host = "None"
	isRemoteServer = False
	removeSupportconfigDir = True
	alloutput = ""
	lineNum = 0
	remoteProgressBarSetup = False
	progressCount = 0
	scHeaderLines = 2
	scTotal = 96 # the number of lines in a standard supportconfig output
	scInterval = int(scTotal / progressBarWidth)

	#if we want to run and analyze a supportconfig
	if len(arg) == 0:
		localHostname = str(os.uname()[1])
		if( loglevel['current'] >= loglevel['normal'] ):
			print(fieldOutput.format('Running Supportconfig On:', localHostname))
		#run supportconfig

		localSupportconfigName = localHostname + "_" + str(dateStamp) + "_" + str(timeStamp)
		localSupportconfigPath = "/var/log/"
		supportconfigPath = localSupportconfigPath + "scc_" + localSupportconfigName

		if( loglevel['current'] >= loglevel['debug'] ):
			print(fieldOutput.format('+ localSupportconfigName', localSupportconfigName))
			print(fieldOutput.format('+ localSupportconfigPath', localSupportconfigPath))
			print(fieldOutput.format('+ supportconfigPath', supportconfigPath))

		try:
			cmd = "supportconfig -bB " + localSupportconfigName + " -t " + localSupportconfigPath
			if( loglevel['current'] >= loglevel['debug'] ):
				print(fieldOutput.format('+ Process Command', cmd))
			p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
		#if we cannot run supportconfig
		except Exception:
			print("Error: Cannot run supportconfig\n", file=sys.stderr)
			return
		condition = True
		if not removeArchive:
			removeSupportconfigDir = False

		if( loglevel['current'] >= loglevel['verbose'] ):
			print(fieldOutput.format('Gathering Supportconfig:', 'In Progress'))
		elif( loglevel['current'] == loglevel['normal'] ):
			sys.stdout.write("Gathering Supportconfig:       [%s]" % (" " * progressBarWidth))
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
				if( loglevel['current'] >= loglevel['verbose'] ):
					sys.stdout.write(out)
					sys.stdout.flush()
				elif( loglevel['current'] == loglevel['normal'] ):
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

		if( loglevel['current'] == loglevel['normal'] ):
			while( progressCount < progressBarWidth ):
				progressCount += 1
				sys.stdout.write("=")
				sys.stdout.flush()
			sys.stdout.write("\n")

	#if a path was given. analyze given file/folder
	elif len(arg) == 1:
		#validate the file/directory/ip given by the end user
		givenSupportconfigPath = arg[0]

		if( givenSupportconfigPath == "." ):
			givenSupportconfigPath = os.getcwd()
		elif( re.search("/", givenSupportconfigPath) ):
			if not os.path.exists(givenSupportconfigPath):
				print(fieldOutput.format('Supportconfig File:', givenSupportconfigPath), file=sys.stderr)
				print("  Error: File/Directory not found", file=sys.stderr)
				print(file=sys.stderr)
				usage()
				return

		if os.path.isfile(givenSupportconfigPath):
			if( loglevel['current'] >= loglevel['normal'] ):
				print(fieldOutput.format('Supportconfig File:', givenSupportconfigPath))
		elif os.path.isdir(givenSupportconfigPath):
			if( loglevel['current'] >= loglevel['normal'] ):
				print(fieldOutput.format('Supportconfig Directory:', givenSupportconfigPath))
			if not removeArchive:
				removeSupportconfigDir = False
		else:
			cmd = "ping -c1 -w1 " + givenSupportconfigPath
			if( loglevel['current'] >= loglevel['normal'] ):
				print(fieldOutput.format('Supportconfig Remote Server:', givenSupportconfigPath))
			if( loglevel['current'] >= loglevel['debug'] ):
				print(fieldOutput.format('+ Process Command', cmd))
			ping_server = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = ping_server.communicate()
			if ping_server.returncode != 0:
				print("  Error: Cannot ping remote server\n", file=sys.stderr)
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
						print("  Error: Unable to reach " + givenSupportconfigPath, file=sys.stderr)
						return
			if host == "None":
				#Not an IP. Lets hope it is a PATH
				supportconfigPath = givenSupportconfigPath
			else:
				#we have an IP
				if( loglevel['current'] >= loglevel['normal'] ):
					print(fieldOutput.format('Running Supportconfig On:', givenSupportconfigPath))
					sys.stdout.write("  Waiting          ")
					sys.stdout.flush()
				remoteSupportconfigName = str(givenSupportconfigPath) + "_" + str(dateStamp) + "_" + str(timeStamp)
				remoteSupportconfigPath = REMOTE_SC_PATH

				#print "lets take a look at that IP "
				try:
					if( len(outputPath) == 0 ):
						outputPath = remoteSupportconfigPath
					#run ssh root@host "supportconfig -R REMOTE_SC_PATH -B <timeStamp>; echo -n \~; cat <path to new supportconfig
					#aka: run supportconfig then send the output back.
					supportconfigPrefix = "/scc_"
					supportconfigCompression = ".txz"
					localSupportconfigFullPath = outputPath + supportconfigPrefix + remoteSupportconfigName + supportconfigCompression
					remoteSupportconfigFullPath = remoteSupportconfigPath + supportconfigPrefix + remoteSupportconfigName + supportconfigCompression

					cmd = "ssh root@" + host + ' /sbin/supportconfig -bB ' + remoteSupportconfigName + ' -R ' + remoteSupportconfigPath + ";echo -n \\~; cat " + remoteSupportconfigFullPath + "; rm " + remoteSupportconfigFullPath + "*"
					if( loglevel['current'] >= loglevel['debug'] ):
						print(fieldOutput.format('\n+ host', host))
						print(fieldOutput.format('+ remoteSupportconfigName', remoteSupportconfigName))
						print(fieldOutput.format('+ remoteSupportconfigPath', remoteSupportconfigPath))
						print(fieldOutput.format('+ supportconfigPrefix', supportconfigPrefix))
						print(fieldOutput.format('+ supportconfigCompression', supportconfigCompression))
						print(fieldOutput.format('+ localSupportconfigFullPath', localSupportconfigFullPath))
						print(fieldOutput.format('+ remoteSupportconfigFullPath  ', remoteSupportconfigFullPath))
						print(fieldOutput.format('+ Process Command', cmd))

					p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
					#create a local verson of the supportconfig output
					localSupportconfig = open(localSupportconfigFullPath, 'w')
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
								if( loglevel['current'] >= loglevel['verbose'] ):
									print(fieldOutput.format('Gathering Supportconfig:', 'In Progress'))
								elif( loglevel['current'] == loglevel['normal'] ):
									sys.stdout.write("Gathering Supportconfig:      [%s]" % (" " * progressBarWidth))
									sys.stdout.flush()
									sys.stdout.write("\b" * (progressBarWidth+1)) # return to start of line, after '['
									sys.stdout.flush()

							if( loglevel['current'] >= loglevel['verbose'] ):
								sys.stdout.write(out.strip("~"))
								sys.stdout.flush()
							elif( loglevel['current'] == loglevel['normal'] ):
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

					if( loglevel['current'] == loglevel['normal'] ):
						if remoteProgressBarSetup:
							while( progressCount < progressBarWidth ):
								progressCount += 1
								sys.stdout.write("=")
								sys.stdout.flush()

					supportconfigPath = localSupportconfigFullPath
					fileInfo = os.stat(supportconfigPath)
					if( fileInfo.st_size > 0 ):
						if( loglevel['current'] >= loglevel['normal'] ):
							print()
							print(fieldOutput.format('Copied Supportconfig:', givenSupportconfigPath + " -> localhost"))
					else:
						print(file=sys.stderr)
						print("Error: Failed to copy supportconfig from remote server", file=sys.stderr)
						print("       Verify you can ssh as root into the remote server", file=sys.stderr)
						print("       and manually copy the supportconfig to this server.", file=sys.stderr)
						print(file=sys.stderr)
						#os.remove(supportconfigPath)
						return
				except Exception:
					print(file=sys.stderr)
					print("  Error: Supportconfig execution failed on " + givenSupportconfigPath + ".", file=sys.stderr)
					return
		else:
			supportconfigPath = givenSupportconfigPath
	supportconfigPath = supportconfigPath.rstrip("/")

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
		extractedSupportconfig = os.path.splitext(base)[0]
	else:
		extractedSupportconfig = base

	if( loglevel['current'] >= loglevel['debug'] ):
		print(fieldOutput.format('+ Base', base))
		print(fieldOutput.format('+ extractedSupportconfig', extractedSupportconfig))
	htmlOutputFile = extractedSupportconfig + "_report.html"

	#if given a supportconfig archive
	if os.path.isfile(supportconfigPath):
		if( loglevel['current'] >= loglevel['debug'] ):
			print(fieldOutput.format('+ Evaluating File', supportconfigPath))
		if( len(outputPath) > 0 ):
			htmlOutputFile = outputPath + "/" + extractedSupportconfig.strip("/").split("/")[-1] + "_report.html"

		#extract file
		#set TarFile and find the path of the soon to be extracted supportconfig
		fileInfo = os.stat(supportconfigPath)
		embeddedPath = ''
		if( fileInfo.st_size > 0 ):
			cmd = "file --brief --mime-type " + supportconfigPath
			if( loglevel['current'] >= loglevel['debug'] ):
				print(fieldOutput.format('+ Process Command', cmd))
			process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
			stdout, stderr = process.communicate()
			if( loglevel['current'] >= loglevel['debug'] ):
				print(fieldOutput.format("+ Detected File Type", stdout))
			if re.search("/x-xz", stdout):
				if supportconfigPath.endswith('.txz'):
					embeddedPath = extractFile(supportconfigPath, "-Jxf")
				elif supportconfigPath.endswith('.tar.xz'):
					embeddedPath = extractFile(supportconfigPath, "-Jxf")
				else:
					print("Error: Unknown xz extension", file=sys.stderr)
					print(file=sys.stderr)
					return
			elif re.search("/x-bzip2", stdout):
				if supportconfigPath.endswith('.tbz'):
					embeddedPath = extractFile(supportconfigPath, "-jxf")
				elif supportconfigPath.endswith('.tar.bz'):
					embeddedPath = extractFile(supportconfigPath, "-jxf")
				elif supportconfigPath.endswith('.tbz2'):
					embeddedPath = extractFile(supportconfigPath, "-jxf")
				elif supportconfigPath.endswith('.tar.bz2'):
					embeddedPath = extractFile(supportconfigPath, "-jxf")
				else:
					print("Error: Unknown bzip2 extension", file=sys.stderr)
					print(file=sys.stderr)
					return
			elif re.search("/x-gzip", stdout):
				if supportconfigPath.endswith('.tgz'):
					embeddedPath = extractFile(supportconfigPath, "-zxf")
				elif supportconfigPath.endswith('.tar.gz'):
					embeddedPath = extractFile(supportconfigPath, "-zxf")
				else:
					print("Error: Unknown gzip extension", file=sys.stderr)
					print(file=sys.stderr)
					return
			elif re.search("/x-tar", stdout):
				embeddedPath = extractFile(supportconfigPath, "-xf")
			else:
				print("  Warning: Unknown supportconfig tar file format", file=sys.stderr)
				print(file=sys.stderr)
				return
		else:
			print("  Error: Zero byte file: " + supportconfigPath, file=sys.stderr)
			print(file=sys.stderr)
			return

	#if given an extracted supportconfig directory
	elif os.path.isdir(supportconfigPath):
		#print(fieldOutput.format('Evaluating Directory:', supportconfigPath))
		#print(fieldOutput.format('+ Directory outputPath:', outputPath))
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


	if os.path.isdir(extractedSupportconfig):
		extractedSupportconfig = extractedSupportconfig + "/"
		if( loglevel['current'] >= loglevel['normal'] ):
			print(fieldOutput.format('Processing Directory:', extractedSupportconfig))
	elif os.path.isdir(embeddedPath):
		extractedSupportconfig = embeddedPath + "/"
		if( loglevel['current'] >= loglevel['normal'] ):
			print(fieldOutput.format('Processing Embedded Directory:', extractedSupportconfig))
	else:
		#not a supportconfig directory or mismatched name
		if( loglevel['current'] >= loglevel['normal'] ):
			print(fieldOutput.format('Processing Directory:', extractedSupportconfig))
		print("  Error: Extracted directory does not match supportconfig filename", file=sys.stderr)
		print(file=sys.stderr)
		return


	#check for required supportconfig files...
	testFile = "basic-environment.txt"
	if not os.path.isfile(extractedSupportconfig + testFile):
		#not a supportconfig. quit out
		print("  Error: Invalid supportconfig archive - missing " + testFile, file=sys.stderr)
		print(file=sys.stderr)
		return

	testFile = "rpm.txt"
	if not os.path.isfile(extractedSupportconfig + testFile):
		#not a supportconfig. quit out
		print("  Error: Invalid supportconfig archive - missing " + testFile, file=sys.stderr)
		print(file=sys.stderr)
		return

	#At this point we should have a extracted supportconfig 
	#run patterns on supportconfig
	runPats(extractedSupportconfig)
	getHtml(htmlOutputFile, extractedSupportconfig, supportconfigPath.split("/")[-1])
	if( loglevel['current'] >= loglevel['normal'] ):
		print(fieldOutput.format('SCA Report File:', htmlOutputFile))

	emailSCAReport(supportconfigPath)

	#clean up
	if( loglevel['current'] >= loglevel['debug'] ):
		print(fieldOutput.format("+ supportconfigPath ",supportconfigPath))
		print(fieldOutput.format("+ removeSupportconfigDir", removeSupportconfigDir))
		print(fieldOutput.format("+ REMOVE_ARCHIVE", REMOVE_ARCHIVE))
		print(fieldOutput.format("+ removeArchive", removeArchive))
	if removeSupportconfigDir:
		shutil.rmtree(extractedSupportconfig)
	if removeArchive:
		if os.path.isfile(supportconfigPath):
			os.remove(supportconfigPath)
			if( loglevel['current'] >= loglevel['normal'] ):
				print(fieldOutput.format('Deleting Supportconfig:', supportconfigPath))
		if os.path.isfile(supportconfigPath + ".md5"):
			os.remove(supportconfigPath + ".md5")
	if( loglevel['current'] >= loglevel['normal'] ):
		print()

##########################################################################################
# main
##########################################################################################
#read in arguments
analyzeServer = False
analyzeLocalServer = False
analyzeFile = ""

# Process command line arguments
if( len(sys.argv[1:]) > 0 ):
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ha:so:rkcqdvpe:")
#		print "opts = " + str(len(opts)) + ", args = " + str(len(args)) + ":" + str(args) + ", sys.argv = " + str(len(sys.argv)) + ", last = " + str(sys.argv[-1])
	except getopt.GetoptError as err:
		# print help information and exit:
		print("Error: " + str(err), file=sys.stderr) # will print something like "option -b not recognized"
		print(file=sys.stderr)
		usage()
		sys.exit(2)

#	print
#	print "Options"
	for startUpOption, startUpOptionValue in opts:
#		print "opts = " + str(len(opts)) + ", args = " + str(len(args)) + ", sys.argv = " + str(len(sys.argv)) + ", startUpOption = " + startUpOption + ", startUpOptionValue = " + startUpOptionValue
		if startUpOption == "-h":
			title()
			usage()
			sys.exit()
		elif startUpOption in ("-p"):
			title()
			patternLibraryList()
			sys.exit()
		elif startUpOption in ("-k"):
			# This is the default behavior, but -k remains for compatibility.
			removeArchive = False
		elif startUpOption in ("-r"):
			removeArchive = True
		elif startUpOption in ("-e"):
			emailAddrList = startUpOptionValue
		elif startUpOption in ("-s"):
			analyzeServer = True
		elif startUpOption in ("-d"):
			loglevel['current'] = loglevel['debug']
		elif startUpOption in ("-q"):
			loglevel['current'] = loglevel['quiet']
		elif startUpOption in ("-v"):
			loglevel['current'] = loglevel['verbose']
		elif startUpOption in ("-a"):
			analyzeFile = startUpOptionValue
			analyzeServer = True
		elif startUpOption in ("-o"):
			outputPath = startUpOptionValue
		else:
			title()
			assert False, "Invalid option"
else:
	title()
	usage()
	sys.exit()

if( loglevel['current'] >= loglevel['normal'] ):
	title()

# an archive was given, but the -a takes priority
if( len(args) > 0 ):
	analyzeServer = True
	if( analyzeFile == "" ):
		analyzeFile = args[0]

if not analyzeServer:
	print("Error: No server to analyze, use -s or specify a supportconfig to analyze or a server to connect.", file=sys.stderr)
	print(file=sys.stderr)
	usage()
	sys.exit()

#validate outputPath
if( len(outputPath) > 0 ):
	if os.path.isdir(outputPath):
		#clean trailing "/"
		if outputPath.endswith("/"):
			outputPath = outputPath[:-1]
	else:
		print("Error: Directory not found -- " + outputPath, file=sys.stderr)
		print(file=sys.stderr)
		print("Use -o path to specify a valid directory", file=sys.stderr)
		print(file=sys.stderr)
		usage()
		sys.exit(2)

if analyzeServer == True and analyzeFile != "":
	analyze(analyzeFile)
elif analyzeServer == True and analyzeFile == "":
	analyze()

