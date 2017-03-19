# SSM
Simple Snort Monitor

This is a simple script for reading snort alerts. You can see a summary of alerts, detail on the alerts, and the full packet that caused the alert. There is also some basic statistics. It can be used on a live snort alerts file or on one created by running snort against a tcpdump capture.

There are two configuration variables at the top of the script:

alert_log=""
snort_logdir=""

Set these variables and, assuming you have snort set up writting to an alert log, that is all the set up needed.

Usage:

./ssm.sh alerts
