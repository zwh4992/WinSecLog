WinSecLog
=========

Windows Security Log Analyzer

Script either calls wevutil for security logs or can be passed an argument for the location of a saved log file
Searches for interesting characteristics, such as multiple failed logins, anonymous logins, long periods of missing logs, etc

REQUIREMENTS:
DateTime module installed for Perl
Windows Vista or newer OS
wevtutil.exe

Syntax: winseclog.pl [file]
