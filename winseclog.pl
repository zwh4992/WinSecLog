#!/usr/bin/perl

use strict;
use warnings;
use DateTime;

#####
#WinSecLog Analyzer
#Zachary Holt - zwh4992@rit.edu
#Script either calls wevutil for security logs or can be passed an argument for the location of a saved log file
#Searches for interesting characteristics, such as multiple failed logins, anonymous logins, long periods of missing logs, etc
#
#REQUIREMENTS:
#DateTime module installed for Perl
#Windows Vista or newer OS
#wevtutil.exe
#
#Ideas for future enhancements:
#  Switches for customized output
#	Hash to correlate number of each Event ID
#	Backwards compatible version?
#	Better date comparison than DateTime?
#	GUI frontend?
#	Expanded list of Event IDs?
#		http://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx - great list of Event IDs
#####

#couple variables we'll use 
#firsttime set to zero as a form of condition evaulation later
my $firsttime = 0;
my $currenttime;
#lasttime will be compared to current to see if a significant time (24h) has gone by since the last log
my $lasttime;
#erid = event record ID - ID of the log file
my $erid;
#eid = event ID - number that correlates to type of event
my $eid;
my @events;

#open file either as RO, or pull directly from wevtutil
if (@ARGV == 1){
	open FILE, "<", $ARGV[0] or die ("\tUnable to open file $ARGV[0]!\n");
}else{
	open (FILE, "wevtutil qe Security |") or die ("\tUnable to run wevtutil!\n");
	
	#determine security log settings if on the local machine
	my @settings = `wevtutil gl Security`;
	print "---- Local Logging Configuration ---\n";
	if ($settings[1] eq "enabled: true\n"){
		print "Logging: Enabled\n";
	}else{
		print "Logging: NOT Enabled!\n";
	}
	if ($settings[8] eq "  retention: true\n"){
		print "Retention: Not being overwritten\n";
	}else{
		print "Retention: Overwriting as needed\n";
	}
	if ($settings[9] eq "  auotBackup: true\n"){
		print "Backup: Enabled\n";
	}else{
		print "Backup: NOT Enabled\n";
	}
	#determine max log size, offsite text space by 11 chars
	$settings[10] = substr($settings[10], 11);
	chomp($settings[10]);
	print "Max log size is: $settings[10] KB\n";
}

print "\n\n--- Begining analysis ---\n";


#read from
while (<FILE>){
	#make sure it's a valid MS XML entry first
	if ($_ =~ m/^\<Event xmlns=.*$/){
		#grab first timestamp
		if ($firsttime eq 0){
			$_ =~ m/(^.*TimeCreated SystemTime=')(.{29})(.*$)/;
			$firsttime = $2;
			#set lasttime as our base time for future comparisons
			$lasttime = $firsttime;
		}
		#grab the basic info of the current event log
		$_ =~ m/(^.*)(EventID\>)(\d{3,4})(.*)(TimeCreated SystemTime=')(.{29})(.*)(EventRecordID\>)(\d{1,})(.*$)/;
		$eid = $3;
		$currenttime = $6;
		$erid = $9;
		
		
		#let's start looking for interesting things!
		#Any log older than the first timestamp would be fishy
		if ($currenttime lt $firsttime){
			push(@events, "$currenttime\t Log with Event Record ID $erid appears to be older than first found log");}
		
		
		#Is current log more than 24 hours apart from last log time?
		#Since the windows log timer isn't standardized format, we do DateTime here
		my $ct = $currenttime;
		$ct =~ m/(\d{4})\-(\d{2})\-(\d{2})T(\d{2})\:(\d{2})\:(\d{2})\.(\d{9})/;
		$ct = DateTime->new(
			year		=> $1,
			month		=> $2,
			day			=> $3,
			hour 		=> $4,
			minute		=> $5,
			second 		=> $6,
			nanosecond 	=> $7,
		);
		my $lt = $lasttime;
		$lt =~ m/(\d{4})\-(\d{2})\-(\d{2})T(\d{2})\:(\d{2})\:(\d{2})\.(\d{9})/;
		$lt = DateTime->new(
			year		=> $1,
			month		=> $2,
			day			=> $3,
			hour 		=> $4,
			minute		=> $5,
			second 		=> $6,
			nanosecond 	=> $7,
		);
		#add 24 hours to lt
		$lt->add( days => 1 );
		#compare if ct > lt+24h
		my $cmp = DateTime->compare( $ct, $lt );
		#datetime returns 1 if param1 is greater than param2
		if ($cmp == 1){ 
			push(@events, "$currenttime\t - Log with Event Record ID $erid appears to more than 24 hours apart from the last log");}
			
		
		#Let's look for a list of interesting eventIDs
		#http://www.ultimatewindowssecurity.com/securitylog/encyclopedia/Default.aspx
		#Cross reference to the above for a good list
		if (($eid == 1100) || ($eid == 1102) || ($eid == 1104)){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Logging issue");}
		if ($eid == 4625){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Acount logon failure");}
		if ($eid == 4649){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Replay attack detected");}
		if ($eid == 4657){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Registry value modified");}
		if (($eid == 4694) || ($eid == 4695)){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Auditable data attempted change");}
		if ($eid == 4697){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Service installed");}
		if (($eid >= 4717) && ($eid <= 4767)){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Account or system modifications");}
		if ($eid == 4780){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - ACL set on Admin account");}
		if ($eid == 4781){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Account name changed");}
		if ($eid == 4782){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Password hash accessed");}
		if ($eid == 4864){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Namespace collision");}
		if ($eid == 4905){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Attempted security event unregistration");}
		if (($eid >=4945) && ($eid <= 4958)){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Windows Firewall modification");}
		if ($eid == 5148){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - DoS detected");}
		if ($eid == 5149){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - DoS attack ended");}
		if ($eid == 5712){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - RPC attempted");}
		if ($eid == 6406){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Windows Firewall took over filtering from another application");}
		if ($eid == 6508){
			push(@events, "$currenttime\t - Log with Event Record ID $erid has interesting Event ID $eid - Application failed and Windows Firewall took over");}
		
			
		
		#if this is a windows restart/user login, and the previous event was 1100 - logging service shutdown - remove that event
		if ($eid =~ /(4608|4624)/){
			if (@events > 0){
				my $checklast = pop(@events);
				if ($checklast =~ m/^.*Event ID 1100.*$/){
					#nothing, things are in the correct order here
				}else{
					#push it back on the array
					push(@events, $checklast);
				}
			}
		}
		
		#Before returning to the top of the loop, set lasttime to match current time for next log
		$lasttime = $currenttime;
	}else{
	#either wasn't MS standard XML for event, or was extraneous data
	}
}

#close our file	
close FILE;

#print array
foreach (@events){
	print $_ . "\n";}
