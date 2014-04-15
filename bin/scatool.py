##############################################################################
# scatool.py - Supportconfig Analysis (SCA) Tool
# Copyright (c) 2014 SUSE LLC
#
# Description:  Runs and analyzes local or remote supportconfigs
# Modified:     2014 Apr 15

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
#     Jason Record (jrecord@suse.com)
#
##############################################################################

import readline
import re
import subprocess
import os 
import sys
import glob
import tarfile
import shutil
import datetime
import socket
import time
import getopt

def title():
	print "################################################################################"
	print "#   SCA Tool v1.0.5-12"
	print "################################################################################"
	print

def usage():
	print "Usage:"
	print " -h      Displays this screen"
	print " -s      Analyze the local server"
	print " -a path Analyze the supportconfig directory or archive"
	print "         The path may also be an IP address of a server to analyze"
	print " -o path HTML report output directory (OUTPUT_PATH)"
	print " -k      Keep archive files (ARCHIVE_MODE)"
	print " -v      Verbose output (LOGLEVEL)"
	print " -c      Enter SCA Tool console (CONSOLE_MODE)"
	print


title()
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
	CONSOLE_MODE = int(os.environ["CONSOLE_MODE"])
except Exception:
	CONSOLE_MODE = 0

try:
	REMOTE_SC_PATH = str(os.environ["REMOTE_SC_PATH"])
except Exception:
	REMOTE_SC_PATH = "/var/log"

try:
	OUTPUT_PATH = str(os.environ["OUTPUT_PATH"])
except Exception:
	OUTPUT_PATH = ""

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
global KeepArchive
global serverName
global verboseMode
global analysisDateTime
knownClasses = []
results = []
patternErrorList = []

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

serverName = "Unknown"
analysisDateTime = datetime.datetime.now()

#order dependent list of pattern output elements
RESULT_ELEMENT = ["META_CLASS", "META_CATEGORY", "META_COMPONENT", "PATTERN_ID", "PRIMARY_LINK", "OVERALL", "OVERALL_INFO", "META_LINK_"]
#commands MUST have a function with the same name.
COMMANDS = ["analyze", "exit", "view", "help"]
#help pages: 
#<command name>: <what it does>\n example: <command example>\n <other info>
COMMANDS_HELP = ["analyze: analyze a supportconfig\nexample: analyze /path/to/supportconfig\nIf no supportconfig is given this will run a supportconfig then analyze the newly created supportconfig",
		 "view: view report files\nexample: view /path/to/report.html\nIf no path given it will try to open newly created report."]
command = ""

def tabSystem(text, size):
	commandBuffer = readline.get_line_buffer()
	compleateCommands = []
	for i in COMMANDS:
		#auto complete to command name
		if i == commandBuffer.split(" ")[0]:
			#if the command has an argument auto complete to path names (unless the command is help)
			if len(commandBuffer.split(" ")) > 0 and commandBuffer.split(" ")[0] != "help":
				if os.path.isdir((glob.glob(commandBuffer.split(" ")[1]+'*'))[size]):
					return (glob.glob(commandBuffer.split(" ")[1]+'*'))[size] + "/"
				return (glob.glob(commandBuffer.split(" ")[1]+'*'))[size]
		if i.startswith(text):
			compleateCommands.append(i)
	if size < len(compleateCommands):
			return compleateCommands[size]
	else:
			return None


#getHeader

#returns html code. This is the about server part.
####example####
#Server Information
#Analysis Date:	2014-04-10 17:45:15
#Archive File:	/home/david/nts_DOCvGRPSdr_130528_1137.html
 
#Server Name:			<Server Name>																		Hardware:							VMware Virtual Platform
#Distribution:		 SUSE Linux Enterprise Server 10 (x86_64)			Service Pack:					4
#OES Distribution: Novell Open Enterprise Server 2.0.3 (x86_64)	OES Service Pack:			3
#Hypervisor:			 VMware (hardware platform)										Identity:							Virtual Machine (hardware platform)
#Kernel Version:	 2.6.16.60-0.99.1-default											Supportconfig Version: 2.25-359

def getHeader(*arg):
	global serverName
	global analysisDateTime
	#reset variables
	supportconfigVersion = ""
	oesVersion = ""
	oesPatchLevel = ""
	OS = ""
	OSVersion = ""
	patchLevel = ""
	kernelVersion = ""
	hardWare = ""
	virtualization = ""
	vmIdentity = ""
	#set timeAnalysis (example: 2014-04-10 17:45:15)
	timeAnalysis = str(analysisDateTime.year) + "-" + str(analysisDateTime.month).zfill(2) + "-" + str(analysisDateTime.day).zfill(2) + " " + str(analysisDateTime.hour).zfill(2) + ":" + str(analysisDateTime.minute).zfill(2) + ":" + str(analysisDateTime.second).zfill(2)
	timeArchiveRun = "0000-00-00 00:00:00"
	returnHTML = ""

	#set archive name if given
	if len(arg) == 3:
		arcName = arg[2]
	else:
		arcName = ""

	#open basic-environment
	File = open(arg[0] + "/basic-environment.txt")
	File.readline()
	File.readline()

	#get supportconfig version
	supportconfigVersion = File.readline().split(':')[-1].strip()

	#read basic-environment line by line to pull out data. (pull: serverName, oesVersion, oesPatchLevel, etc)
	while True:
		line = File.readline()
		if not line:
			break

		#get hardWare
		if line.startswith("Hardware:"):
			hardWare = line.split(":")[1].strip()

		#get virtualization
		if line.startswith("Hypervisor:"):
			virtualization = line.split(":")[1].strip()

		#get virtualization identity
		if line.startswith("Identity:"):
			vmIdentity = line.split(":")[1].strip()

		#get supportconfig run date and time
		if "/bin/date" in line:
			tmp = File.readline().split(" ")
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

		#get kernel version and server name
		if "/bin/uname -a" in line:
			tmp = File.readline().split(" ")
			kernelVersion = tmp[2].strip()
			serverName = tmp[1].strip()

		#get OS Version and patch level
		if "/etc/SuSE-release" in line:
			OS = File.readline().strip()
			OSVersion = File.readline().split('=')[-1].strip()
			patchLevel = File.readline().split('=')[-1].strip()

		#get OES version and pathch level
		if "/etc/novell-release" in line:
			oesVersion = File.readline().strip()
			if "Open Enterprise" in oesVersion:
				#we don't need the oes version just SP so skip the next line
				File.readline()
				oesPatchLevel = File.readline().split('=')[-1].strip()
			else:
				oesVersion = ''
	File.close()

	#create HTML from the data we just got
	returnHTML = returnHTML + '<H1>Supportconfig Analysis Report</H1>\n'
	returnHTML = returnHTML + '<H2><HR />Server Information</H2>\n'

	returnHTML = returnHTML + '<TABLE WIDTH=100%>\n'
	returnHTML = returnHTML + '<TR><TD><B>Analysis Date:</B></TD><TD>'
	returnHTML = returnHTML + timeAnalysis
	returnHTML = returnHTML + '</TD></TR>\n'
	returnHTML = returnHTML + '<TR><TD><B>Supportconfig Run Date:</B></TD><TD>'
	returnHTML = returnHTML + timeArchiveRun
	returnHTML = returnHTML + '</TD></TR>\n'
	returnHTML = returnHTML + '<TR><TD><B>Supportconfig File:</B></TD><TD>'
	returnHTML = returnHTML + arcName
	returnHTML = returnHTML + '</TD></TR>\n'
	returnHTML = returnHTML + '</TABLE>\n'

	returnHTML = returnHTML + '<TABLE CELLPADDING="5">\n'

	returnHTML = returnHTML + '<TR><TD>&nbsp;</TD></TR>\n'

	returnHTML = returnHTML + '<TR></TR>\n'

	#Server name and hardWare
	returnHTML = returnHTML + '<TR><TD><B>Server Name:</B></TD><TD>'
	returnHTML = returnHTML + serverName
	returnHTML = returnHTML + '</TD><TD><B>Hardware:</B></TD><TD>'
	returnHTML = returnHTML + hardWare
	returnHTML = returnHTML + '</TD></TR>\n'

	#OS and PatchLevel
	returnHTML = returnHTML + '<TR><TD><B>Distribution:</B></TD><TD>'
	returnHTML = returnHTML + OS
	returnHTML = returnHTML + '</TD><TD><B>Service Pack:</B></TD><TD>'
	returnHTML = returnHTML + patchLevel
	returnHTML = returnHTML + '</TD></TR>\n'

	if oesVersion != "":
		#OES version and OES patchLevel
		returnHTML = returnHTML + '<TR><TD><B>OES Distribution:</B></TD><TD>'
		returnHTML = returnHTML + oesVersion
		returnHTML = returnHTML + '</TD><TD><B>OES Service Pack:</B></TD><TD>'
		returnHTML = returnHTML + oesPatchLevel
		returnHTML = returnHTML + '</TD></TR>\n'

	if virtualization != "None" and virtualization != "":
		#hypervisor stuff
		returnHTML = returnHTML + '<TR><TD><B>Hypervisor:</B></TD><TD>'
		returnHTML = returnHTML + virtualization
		returnHTML = returnHTML + '</TD><TD><B>Identity:</B></TD><TD>'
		returnHTML = returnHTML + vmIdentity
		returnHTML = returnHTML + '</TD></TR>\n'

	#kernel Version and Supportconfig version
	returnHTML = returnHTML + '<TR><TD><B>Kernel Version:</B></TD><TD>'
	returnHTML = returnHTML + kernelVersion
	returnHTML = returnHTML + '</TD><TD><B>Supportconfig Version:</B></TD><TD>'
	returnHTML = returnHTML + supportconfigVersion
	returnHTML = returnHTML + '</TD></TR>\n'
	returnHTML = returnHTML + '</TABLE>\n'
	returnHTML = returnHTML + '<HR />\n'
	return returnHTML

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

#determines which patterns apply to the supportconfig
#returns a list of applicable patterns
def patternPreProcessor(extractedSupportconfig):
	global verboseMode
	patternFileList = []
	patternDirectories = [SCA_PATTERN_PATH + "/local/"] #always include the local patterns

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
	for lineNumber in range(0, len(basicEnvLines)):
		if inSLES:
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
	hae = re.compile("^heartbeat[[:space:]]|^openais[[:space:]]|^pacemaker[[:space:]]")
	for line in RPMs:
		if hae.search(line) and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/HAE/"))
		if "NDSserv " in line and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/eDirectory/"))
		if "groupwise " in line and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/GroupWise/"))
		if "datasync-common " in line and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/GroupWise/"))
		if "filr-famtd " in line and not line.startswith("sca-patterns"):
			patternDirectories.append(str(SCA_PATTERN_PATH + "/Filr/"))

	systemDefinition = []
	for systemElement in patternDirectories:
		systemDefinition.append(systemElement.split("/")[-2])
	print "Pattern Definitions:          " + " ".join(systemDefinition)

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


#run all patterns
#this is called by analyze.
#does not return anything; however, it does set results[]
def runPats(extractedSupportconfig):
	global results
	global patternErrorList
	global verboseMode
	results = []

	validPatterns = patternPreProcessor(extractedSupportconfig)

	progressBarWidth = 48
	progressCount = 0
	patternCount = 0
	patternTotal = len(validPatterns)
	patternInterval = int(patternTotal / progressBarWidth)

	print "Total Patterns to Apply:      " + str(patternTotal)
	if verboseMode:
		print "Analyzing Supportconfig:      In Progress"
	else:
		sys.stdout.write("Analyzing Supportconfig:      [%s]" % (" " * progressBarWidth))
		sys.stdout.flush()
		sys.stdout.write("\b" * (progressBarWidth+1)) # return to start of line, after '['

	for patternFile in validPatterns:
		patternCount += 1
		try:
			p = subprocess.Popen([patternFile, '-p', extractedSupportconfig], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			out, error = p.communicate()
			patternValidated = parseOutput(out, error, patternFile)

			#call parseOutput to see if output was expected
			if verboseMode:
				if patternValidated:
					print " Done:  " + str(patternCount) + " of " + str(patternTotal) + ": " + patternFile
				else:
					print " ERROR: " + str(patternCount) + " of " + str(patternTotal) + ": " + patternErrorList[-1]
			else:
				#advance the progress bar if it's not full yet
				if( progressCount < progressBarWidth ):
					#advance the progress bar in equal intervals
					if( patternCount % patternInterval == 0 ):
						progressCount += 1
						sys.stdout.write("=")
						sys.stdout.flush()
		except Exception:
			patternErrorList.append(patternFile + " -- Pattern runtime error")
			if verboseMode:
				print " ERROR: " + str(patternCount) + " of " + str(patternTotal) + ": " + patternErrorList[-1]

	#make output look nice
	if not verboseMode:
		while( progressCount < progressBarWidth ):
			progressCount += 1
			sys.stdout.write("=")
			sys.stdout.flush()
	sys.stdout.write("\n")

	print "Applicable Patterns:          " + str(len(results))
	print "Pattern Execution Errors:     " + str(len(patternErrorList))
	if not verboseMode:
		for patternErrorStr in patternErrorList:
			print "  " + patternErrorStr

#find all class Names in results
#does not return anything
#side effect: set "knownClasses"
def getClasses():
	global knownClasses
	global results
	#reset knownClasses
	knownClasses = []
	for i in range(len(results)):
		if not (results[i][0].split("=")[1] in knownClasses):
			knownClasses.append(results[i][0].split("=")[1])

	
	
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
	}\n\
	</SCRIPT>"

	#add stuff to html.. :)
	HTML = HTML + script + "\n"
	HTML = HTML + "</HEAD>" + "\n"
	
	#get header html
	HTML = HTML + "<BODY BGPROPERTIES=FIXED BGCOLOR=\"#FFFFFF\" TEXT=\"#000000\">" + "\n"
	HTML = HTML + getHeader(archivePath, OutPutFile, archiveFile)

	# getHeader probes the archive for serverName, so the header has to be retrieved after getHeader is called.
	# temporarily storing header in HTML_HEADER
	#html top bit:
	HTML_HEADER = HTML_HEADER + "<!DOCTYPE html>" + "\n"
	HTML_HEADER = HTML_HEADER + "<HTML>" + "\n"
	HTML_HEADER = HTML_HEADER + "<HEAD>" + "\n"
	HTML_HEADER = HTML_HEADER + "<TITLE>SCA Report for " + serverName + "</TITLE>" + "\n"
	HTML_HEADER = HTML_HEADER + "<STYLE TYPE=\"text/css\">" + "\n"
	HTML_HEADER = HTML_HEADER + "  a {text-decoration: none}  /* no underlined links */" + "\n"
	HTML_HEADER = HTML_HEADER + "  a:link {color:#0000FF;}  /* unvisited link */" + "\n"
	HTML_HEADER = HTML_HEADER + "  a:visited {color:#0000FF;}  /* visited link */" + "\n"
	HTML_HEADER = HTML_HEADER + "</STYLE>" + "\n"
	HTML_HEADER = HTML_HEADER + HTML
	HTML = HTML_HEADER
	
	#Critical table
	HTML = HTML + '<H2>Conditions Evaluated as Critical<A NAME="Critical"></A></H2>' + "\n"
	HTML = HTML + '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML = HTML + '<TR COLOR="#000000"><TH BGCOLOR="#FF0000"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#FF0000"></TH></TR>' + "\n"
	HTML = HTML + getTableHtml(4)
	HTML = HTML + "</TABLE>" + "\n"
	
	#Warning table
	HTML = HTML + '<H2>Conditions Evaluated as Warning<A NAME="Warning"></A></H2>' + "\n"
	HTML = HTML + '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML = HTML + '<TR COLOR="#000000"><TH BGCOLOR="#FFFF00"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#FFFF00"></TH></TR>' + "\n"
	HTML = HTML + getTableHtml(3)
	HTML = HTML + "</TABLE>" + "\n"
	
	#Recommended table
	HTML = HTML + '<H2>Conditions Evaluated as Recommended<A NAME="Recommended"></A></H2>' + "\n"
	HTML = HTML + '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML = HTML + '<TR COLOR="#000000"><TH BGCOLOR="#1975FF"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#1975FF"></TH></TR>' + "\n"
	HTML = HTML + getTableHtml(1)
	HTML = HTML + "</TABLE>" + "\n"
	
	#Success table
	HTML = HTML + '<H2>Conditions Evaluated as Success<A NAME="Success"></A></H2>' + "\n"
	HTML = HTML + '<TABLE STYLE="border:3px solid black;border-collapse:collapse;" WIDTH="100%" CELLPADDING="2">' + "\n"
	HTML = HTML + '<TR COLOR="#000000"><TH BGCOLOR="#00FF00"></TH><TH BGCOLOR="#EEEEEE" COLSPAN="3">Category</TH><TH>Message</TH><TH>Solutions</TH><TH BGCOLOR="#00FF00"></TH></TR>' + "\n"
	HTML = HTML + getTableHtml(0)
	HTML = HTML + "</TABLE>" + "\n"
	
	#HTML end stuff
	HTML = HTML + "</BODY>" + "\n"
	HTML = HTML + "</HTML>" + "\n"
	
	#write HTML to the output file
	fh = open(OutPutFile, "w")
	fh.write(HTML)
	fh.close()
 
#takes a status(critical (4), warning (3), etc) and returns the corresponding table... in html
def getTableHtml(val):
	#reset number of hits. ( a hit in this case is a result that matches "val")
	numHits = 0
	#set the color.
	if val == 4:
		#red (critical)
		color = "FF0000"
	elif val == 3:
		#yellow (warning)
		color = "FFFF00"
	elif val == 1:
		#blue.. ish (recommended)
		color = "1975FF"
	elif val == 0:
		#green (success)
		color ="00FF00"
	else:
		#fallback (gray)
		color = "222222"
	 

	returnString = ""
	tmpReturn = ""
	
	#sort by known classes
	for Class in knownClasses:
		numHits = 0
		tmpReturn = ""
		#for all results
		for i in range(len(results)):
			#for results of a pattern
			if results[i][0].split("=")[1] == Class and int(results[i][5].split("=")[1]) == val:
				numHits = numHits + 1
				#find main link
				Main_Link = ""
				for j in range(len(results[i])):
					#if main link
					if results[i][j].split('=')[0] == results[i][4].split("=")[1]:
						
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
				for link in range(7, len(results[i])):
					linkUrl = ""
					#remove the stuff before the first "="
					tmp2 = results[i][link].split("=")
					linkName = tmp2[0].split("_")[-1]
					del tmp2[0]
					for LinkPart in tmp2:
						linkUrl = linkUrl + "=" + LinkPart
					#clean up the "=" leftover
					linkUrl = linkUrl.strip("=")
					
					#put it in html form
					links = links + '<A HREF="' + linkUrl + '" TARGET="_blank">' + linkName + " " + '</A>'
				tmpReturn = tmpReturn + ('<TR STYLE="border:1px solid black; background: #FFFFFF; display:none;" CLASS="'\
					+ Class + \
						'"><TD BGCOLOR="#'\
					+ color +\
						'" WIDTH="2%">&nbsp;</TD><TD BGCOLOR="#EEEEEE" WIDTH="6%">'\
					+ results[i][0].split("=")[1] + \
					'</TD><TD BGCOLOR="#EEEEEE" WIDTH="5%">'\
					+ results[i][1].split("=")[1] + \
					'</TD><TD BGCOLOR="#EEEEEE" WIDTH="5%">'\
					+ results[i][2].split("=")[1] +\
					'</TD><TD><A HREF="'\
					+ Main_Link + \
					'" TARGET="_blank">'\
					+ results[i][6].split("=")[1] +\
					 '</A>&nbsp;&nbsp;<A HREF="https://code.google.com/p/server-diagnostic-patterns/source/browse/trunk/patterns/'
					+results[i][0].split("=")[1] +\
					 '/all/' \
					+ results[i][3].split("=")[1] +\
							 '" TARGET="_blank">&nbsp;</A></TD><TD WIDTH="8%">'\
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
			+ str(numHits) + " " + Class + " Message(s)" +\
			'</A></TD><TD WIDTH="8%">&nbsp;</TD><TD BGCOLOR="#'\
			+ color +\
			'" WIDTH="2%">&nbsp;</TD></TR>'\
			+ "\n" +tmpReturn)
			returnString = returnString + tmpReturn
	#well that was fun... return
	return(returnString)
	

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
			results.append(output)
		return True
	else:
		patternErrorList.append(pat + " -- Output error: " + str(error.split("\n")[0]))
		return False

#############################################################################
# analyze
#############################################################################
#analyze server or supportconfig
def analyze(*arg):
	global outputPath
	global htmlOutputFile
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
	extractedPath = ""
	deleteArchive = False
	isIP = False
	host = "None"
	isRemoteServer = False
	cleanUp = True
	
	#if we want to run and analyze a supportconfig
	if len(arg) == 0:
		print "Running Supportconfig On:     localhost"
		#run supportconfig
		try:
			p = subprocess.Popen(['/sbin/supportconfig', '-b'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			#remove archive
			deleteArchive = True
		#if we cannot run supportconfig
		except Exception:
			print >> sys.stderr, "Error: Cannot run supportconfig. Please see http://www.novell.com/communities/node/2332/supportconfig-linux#install"
			print >> sys.stderr
			return
		condition = True
		alloutput = ""
		lineNum = 0
		supportconfigPath = ""
		
		#this acts like a do-while. I love do-while :)
		#print output of the subprocess (supportconfig)
		#--DO--
		while condition:
			out = p.stdout.read(1)
			if out != '':
					sys.stdout.write(out)
					alloutput = alloutput + out
					sys.stdout.flush()
					if out == "\n":
						lineNum = lineNum + 1
						
		#--WHILE--
			condition = not bool(out == "" and p.poll() != None)
			
		#find tar ball
		for line in alloutput.split("\n"):
			if "Log file tar ball:" in line:
				supportconfigPath = line.split(":")[1].strip()
		#just used for consistency compared to a remote server supportconfig, where ~ is needed to indentify the the supportconfig termination
		print "~"
	#if a path was given. analyze given file/folder
	elif len(arg) == 1:
		#validate the file/folder/ip given by the end user
		givenSupportconfigPath = arg[0]

		if os.path.isfile(givenSupportconfigPath):
			print "Supportconfig File:           %s" % givenSupportconfigPath
		elif os.path.isdir(givenSupportconfigPath):
			print "Supportconfig Directory:      %s" % givenSupportconfigPath
		else:
			print "Supportconfig Remote Server:  %s" % givenSupportconfigPath
			ping_server = subprocess.Popen(["/bin/ping", "-c1", givenSupportconfigPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			streamdata = ping_server.communicate()[0]
			if ping_server.returncode != 0:
				print >> sys.stderr, "Error: Invalid Supportconfig: " + givenSupportconfigPath
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
						print >> sys.stderr, "Error: Unable to reach " + givenSupportconfigPath
						return
			if host == "None":
				#Not an IP. Lets hope it is a PATH
				supportconfigPath = givenSupportconfigPath
			else:
				#we have an IP
				print "Running Supportconfig On:     " + givenSupportconfigPath
				print "Enter Your Credentials For:   " + givenSupportconfigPath
				remoteSupportconfigName = str(givenSupportconfigPath) + "_" + str(dateStamp) + "_" + str(timeStamp)
				remoteSupportconfigPath = REMOTE_SC_PATH
				
				#print "lets take a look at that IP "
				try:
					if( len(outputPath) == 0 ):
						outputPath = remoteSupportconfigPath
					#run ssh root@host "supportconfig -R REMOTE_SC_PATH -B <timeStamp>; echo -n \~; cat <path to new supportconfig
					#aka: run supportconfig then send the output back.
					p = subprocess.Popen(['ssh', "root@" + host, 'supportconfig -R ' + remoteSupportconfigPath + ' -B ' + str(remoteSupportconfigName) + ";echo -n \\~; cat " + remoteSupportconfigPath + "/nts_" + str(remoteSupportconfigName) + ".tbz" + "; rm " + remoteSupportconfigPath + "/nts_" + str(remoteSupportconfigName) + ".tbz*"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
								#print non binary data to stdout
								sys.stdout.write(out)
								sys.stdout.flush()
						#if we are ate the end of the file output
						if out == "~":
							endOfSupportconfig = True
									
					#--WHILE--
						condition = not bool(out == "" and p.poll() != None)
					#close the local copy of the remote supportconfig.
					localSupportconfig.close()
					supportconfigPath = outputPath + "/nts_" + str(remoteSupportconfigName) + ".tbz"
					fileInfo = os.stat(supportconfigPath)
					if( fileInfo.st_size > 0 ):
						print
						print "Copied Supportconfig:         " + givenSupportconfigPath + " -> localhost"
					else:
						print >> sys.stderr, "Error: Failed to copy supportconfig from remote server"
						print >> sys.stderr
						os.remove(supportconfigPath)
						return
				except Exception:
					print >> sys.stderr, "Error: Cannot run supportconfig on " + arg[0] + "."
					return
		else:
			supportconfigPath = givenSupportconfigPath
	else:
		#too many arguments
		print >> sys.stderr, "Please run: \"help analyze\""
		
	if not supportconfigPath.startswith("/") and not supportconfigPath.startswith("./"):
		supportconfigPath = "./" + supportconfigPath
	#if supportconfig not extract. Extract supportconfig
	if os.path.isfile(supportconfigPath):
		#extract file
		#find the extracting path
		tmp = supportconfigPath.split('/')
		del tmp[-1]
		extractedPath = '/'.join(tmp) 
		#set TarFile and find the path of the soon to be extracted supportconfig
		try:
			fileInfo = os.stat(supportconfigPath)
			if( fileInfo.st_size > 0 ):
				print "Extracting Supportconfig:     " + supportconfigPath
				TarFile = tarfile.open(supportconfigPath, "r:*")
				extractedSupportconfig = extractedPath + "/" + TarFile.getnames()[0].split("/")[-2] + "/"
				if( len(outputPath) > 0 ):
					htmlOutputFile = outputPath + "/" + TarFile.getnames()[0].split("/")[-2] + ".html"
				else:
					htmlOutputFile = extractedPath + "/" + TarFile.getnames()[0].split("/")[-2] + ".html"
				TarFile.extractall(path=extractedPath, members=None)
				print "Supportconfig Directory:      " + extractedSupportconfig 
			else:
				print >> sys.stderr, "Error: Zero byte file: " + supportconfigPath
				print >> sys.stderr
				return
		except tarfile.ReadError:
			#cannot open the tar file
			print >> sys.stderr, "Error: Invalid supportconfig archive: " + supportconfigPath
			print >> sys.stderr
			return
	#if given an extracted supportconfig
	elif os.path.isdir(supportconfigPath):
		extractedSupportconfig = supportconfigPath
		if( len(outputPath) > 0 ):
			htmlOutputFile = outputPath + "/" + extractedSupportconfig.strip("/").split("/")[-1] + ".html"
		else:
			htmlOutputFile = extractedSupportconfig
			if htmlOutputFile.endswith("/"):
				htmlOutputFile = htmlOutputFile[:-1]
			tmp = htmlOutputFile.split("/")
			del tmp[-1]
			htmlOutputFile = "/".join(tmp) + "/" + extractedSupportconfig.strip("/").split("/")[-1] + ".html"
		#we don't want to delete something we did not create.
		cleanUp = False

	#check for required supportconfig files...
	testFile = "/basic-environment.txt"
	if not os.path.isfile(extractedSupportconfig + testFile):
		#not a supportconfig. quit out
		print >> sys.stderr, "Error:   Invalid supportconfig archive"
		print >> sys.stderr, "Missing: " + supportconfigPath + testFile
		print >> sys.stderr
		return

	testFile = "/rpm.txt"
	if not os.path.isfile(extractedSupportconfig + testFile):
		#not a supportconfig. quit out
		print >> sys.stderr, "Error:   Invalid supportconfig archive"
		print >> sys.stderr, "Missing: " + supportconfigPath + testFile
		print >> sys.stderr
		return
	
	#At this point we should have a extracted supportconfig 
	#run patterns on supportconfig
	runPats(extractedSupportconfig)
	getHtml(htmlOutputFile, extractedSupportconfig, supportconfigPath.split("/")[-1])
	print ("SCA Report File:              %s" % htmlOutputFile)
	print

	#if command was run via console run view
	if command != "exit":
		print "run \"view\" or open " + htmlOutputFile + " to see results"
		view()

	#clean up
	if cleanUp:
		shutil.rmtree(extractedSupportconfig)
	if deleteArchive and not KeepArchive:
		os.remove(supportconfigPath)
		if os.path.isfile(supportconfigPath + ".md5"):
			os.remove(supportconfigPath + ".md5")
			
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

#read in arguments
analyzeServer = False
analyzeFile = ""
#Do not enter console unless given a -c

# Process command line arguments
if( len(sys.argv[1:]) > 0 ):
	try:
		opts, args = getopt.getopt(sys.argv[1:], "ha:so:kcv")
	except getopt.GetoptError as err:
		# print help information and exit:
		print "Error: " + str(err) # will print something like "option -b not recognized"
		print
		usage()
		sys.exit(2)


	autoExit = True
	analyzeServer = False
	analyzeFile = ""
	for startUpOption, startUpOptionValue in opts:
		if startUpOption == "-h":
			usage()
			sys.exit()
		elif startUpOption in ("-k"):
			KeepArchive = True
		elif startUpOption in ("-c"):
			autoExit = False
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
elif( CONSOLE_MODE > 0 ):
	autoExit = False
else:
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

#auto exit.. or not:
#if autoExit and analyzeServer:
if autoExit:
	command = "exit"
if analyzeServer == True and analyzeFile != "":
	analyze(analyzeFile)
elif analyzeServer == True and analyzeFile == "":
	analyze()

#get user input:
readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
#tell readline to use tab complete stuff
readline.set_completer(tabSystem)
#main command line input loop
while command != "exit":
	#get command (this will use the auto-complete I created.)
	command = raw_input("^^~ ")
	#run the command: <argument1>(<argument2>): example "analyze /home/support/nts_123456.tbz" will call "analyze(/home/support/nts_123456.tbz)"
	if len(command.split(" ")) > 1:
		if command.split(" ")[0] in COMMANDS:
			eval(command.split(" ")[0] + "(\"" + command.split(" ")[1] + "\")")
		else:
			print >> sys.stderr, command.split(" ")[0] + " command not found, please run \"help\""
	else:
		if command in COMMANDS:
			eval(command + "()")
		else:
			print >> sys.stderr, command + " command not found, please run \"help\""

