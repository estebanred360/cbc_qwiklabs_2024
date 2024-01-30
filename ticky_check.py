#!/usr/bin/env python3

import re
import os
import sys
import subprocess
import operator


per_user_logs = {}  #  number of log entries for each user (splitting between INFO and ERROR)

user_dic_columns = ["Username", "INFO.ERROR"]

per_user_logs["username"] = []
per_user_logs["INFO.ERROR"] = [0.0]


error_counts={}  # number of different error messages

error_columns = ["Error", "Count"]

error_dic_keys = ["Timeout while retrieving information",
                "The ticket was modified while updating",
                "Connection to DB failed",
                "Tried to add information to a closed ticket",
                "Permission denied while closing ticket",
                "Ticket doesn't exist"]

# Dico initialisation

for i in range(len(error_dic_keys)):
	print("Possible error messages: "+ str(i) +"/"+ str(len(error_dic_keys))+ ". - " + error_dic_keys[i] + "\n")

def count_logs(param):
    if param == "ERROR":
        # HACER
        return "hola error"
    elif param == "INFO":
        # HACER
        return "hola info"

logfile = sys.argv[1]
with open(logfile) as lgf:
	for line in lgf:
		if "ticky" in line:
			print("new ticky line: " + line)
			#continue
		if "ERROR" in line:
			# count errors
			#message = re.search(r"(ticky: ERROR: )([\w ]*)\s\((.*?)\)$", line)
			message="hello"
			print(message)
			if message in None:
				continue
			print("inerror")
			#error_counts[message] = error_counts.get(message, 0) + 1

			# log entry per user
			username = re.search(r"(ticky: ERROR: )([\w ]*)\s\((.*?)\)$", line)
			print(username)
			per_user_logs[username] = count_logs("ERROR")
			continue

		elif "INFO" in line:
			# log entry per user
			username = re.search(r"(ticky: INFO: )([\w ]*)\s(\[[#]\d{4}\])\s\((.*?)\)$", line)
			print(username)
			message = re.search(r"(ticky: INFO: )([\w ]*)\s(\[[#]\d{4}\])\s\((.*?)\)$", line)
			print(message)
			per_user_logs[username] = count_logs("INFO")
			continue

		else:
			print("unexpected log entry")
			continue
lgf.close()

