import pandas as pd
import argparse
import os
import time
from datetime import date, timedelta
import base64
import json
import sys
import requests
requests.packages.urllib3.disable_warnings()


import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler


# GLOBALS SECTION
QUERY_DELAY = 300 # Every 5 minutes
HEARBEAT = 120 # Every two minutes
logFile=os.curdir + os.sep + 'log' + os.sep + 'observer.log'
logger = ""

class McAfee_SIEM():

	def __init__(self,esmserver):
		'''
		Description: Constructor
		Input:       IP address of SIEM Server
		Output:      No Output
		'''
		self.esmserver   = esmserver
		self.user 		 = ''
		self.password    = ''
		
		self.auth_header = {}

	def connect(self, user, password):
		'''
		Description: Connection method, stablish a connection to the esm server and populates all 
			     self variables of the constructor
		Input:       User and password
		Output:      Two possible values: 
			     (0, error_info): Unsucessful connection, error_info contain the cause of the error
			     (1, 'Connection sucessful): Sucessful connection
		'''

		self.user 		= user
		self.password 	= password

		url = 'https://{}/rs/esm/v2/login'.format(self.esmserver)

		header = {'Content-Type': 'application/json'}

		# Building data parameters
		v10_b64_user     = base64.b64encode(self.user.encode('utf-8')).decode()
		v10_b64_password = base64.b64encode(self.password.encode('utf-8')).decode()

		data = {"username": v10_b64_user, 
        	    "password": v10_b64_password,
        	    "locale": "en_US",
        	    "os":"Win32"}

		# Connect to the REST API
		try:
			r = requests.post(url, data=json.dumps(data), headers=header, verify=False)

		except requests.exceptions.ConnectionError:
			error_info = 'Connection - ESM connection error'
			return (0, error_info)

		if r.status_code in [200,201]:
			# With the information obtained we build the authenticated header 
			# This auth_headerwill be used in further calls to the API
			self.auth_header                 = {'Content-Type': 'application/json'}
			self.auth_header['Cookie']       = r.headers.get('Set-Cookie')
			self.auth_header['X-Xsrf-Token'] = r.headers.get('Xsrf-Token')

		else:
			# login error
			error_info = "Error connecting to ESM, status code: %s"%r.status_code
			return (0, error_info)

		return (1, "Connection Sucessful")

	def disconnect(self):
		'''
		Description: Disconnection method.
		Input:       No input
		Output:      Two possible values: 
			     (0, error_info): Unsucessful disconnection, error_info contain the cause of the error
			     (1, 'Disconnection sucessful): Sucessful disconnection
		'''	
		url = 'https://{}/rs/esm/v2/logout'.format(self.esmserver)
		
		try:
			r = requests.delete(url, headers = self.auth_header, verify=False)
		except requests.exceptions.ConnectionError:
			error_info = "Disconnection - ESM connection error"
			return (0, error_info)

		if r.status_code == 200:
			return(1,'Disconnection successful')
		else:
			error_info = 'ESM disconnection error, Status Code: %d'%r.status_code
			return(0, error_info)

	def keepAlive(self):
		'''
		Description: Keep alive method.
		Input:       No input
		Output:      Two possible values: 
			     (0, error_info): Unsucessful keepalive, error_info contain the cause of the error
			     (1, 'keepAlive sucessful): Sucessful keepalive
		'''	
		url = 'https://{}/rs/esm/v2/miscKeepAlive'.format(self.esmserver)
		
		try:
			r = requests.post(url, headers = self.auth_header, verify=False)
		except requests.exceptions.ConnectionError:
			error_info = "KeepAlive - ESM connection error"
			return (0, error_info)

		if r.status_code == 200:
			return(1,'KeepAlive successful')
		else:
			error_info = 'KeepAlive error, Status Code: %d'%r.status_code
			return(0, error_info)

	def esm_query(self, filters=None, fields=None, time_range="LAST_HOUR", limit=0, total=False):
		'''
		Description: ESM query method.
		Input:       filters --> Set of fields to filter the query by
					 fields  --> Set of fields to be obtained
					 time_range --> Period of time to be queried
					 l
		Output:      Two possible values: 
			     (0, error_info): Unsucessful esm query, error_info contain the cause of the error
			     (1, resultID): Job ID, this identificator is necessary to later data retrieval.
		'''	
		'''
			Accepted values for time range

				LAST_MINUTE
				LAST_10_MINUTES
				LAST_30_MINUTES
				LAST_HOUR
				CURRENT_DAY
				PREVIOUS_DAY
				LAST_24_HOURS
				LAST_2_DAYS
				LAST_3_DAYS
				CURRENT_WEEK
				PREVIOUS_WEEK
				CURRENT_MONTH
				PREVIOUS_MONTH
				CURRENT_QUARTER
				PREVIOUS_QUARTER
				CURRENT_YEAR
				PREVIOUS_YEAR
		'''
		url = "https://{}/rs/esm/v2/qryExecuteDetail?type=EVENT&reverse=false".format(self.esmserver)

		list_of_fields  = []
		list_of_filters = []

		if fields:
		    for each_field in fields:
		        list_of_fields.append({'name': each_field})
		else:
		    list_of_fields = []


		if filters:
		    list_of_filters.append({"type": "EsmFieldFilter","field": {"name": filters['field']}, 
		                            "operator": filters['operator'], 
		                            "values":[{"type": "EsmBasicValue", "value": filters['values']}]
		                          })
		else:
		    list_of_filters = []

		order = [{
		         "direction": "DESCENDING", 
		         "field": {"name": "LastTime"}
		        }]


		payload =  {'config' : 
		                    {
		                    'timeRange'    : time_range,
		                    'order'        : order,
		                    'includeTotal' : total,
		                    'fields'       : list_of_fields,
		                    'filters'      : list_of_filters,
		                    'limit'        : limit
		                    }
		                }

		try:
			r = requests.post(url, data = json.dumps(payload), headers=self.auth_header, verify=False)
		except requests.exceptions.ConnectionError:
			error_info = "ESM query - ESM connection Error"
			return(0, error_info)

		if r.status_code == 200:
			r = r.json()
			return (1, r['resultID'])
		else:
			print("Debug - ESM query error", r.text )		
			error_info = "ESM query error, Status Code: %d"%r.status_code
			return(0, error_info)			

	def query_status(self, resultID):
		'''
		Description: Query status
		Input:       resultId, identying a queries executed against de REST API
		Output:      Two possible values: 
			     	 (0, error_info): Error getting the status of the query, error_info contain the cause of the error
			     	 (1, resultID sucessfully finished)
			     	 (2, Job not ready for data retrieval)
		'''	

		data = {'resultID': resultID}

		url = 'https://{}/rs/esm/v2/qryGetStatus'.format(self.esmserver)

		try:
			r = requests.post(url, data = json.dumps(data), headers=self.auth_header, verify=False)
		except requests.exceptios.ConnectionError:
			error_info = "Query Status - ESM connection Error"
			return(0, error_info)

		if r.status_code == 200:
			r = r.json()
			if not r["complete"]:
				return(2, "Job %snot ready for data retrieval"%resultID)
			else:
				return(1, "Job %s status %s %% in %s Miliseconds"%(resultID, r["percentComplete"], r["milliseconds"]))
		else:
			error_info = "Query Status error, Status Code: %d"%r.status_code
			return(0, error_info)			

	def get_query_results(self, resultID):
		'''
		Description: Get the query restuls
		Input:       resultId, identying a queries executed against de REST API
		Output:      Two possible values: 
			     	 (0, error_info): Error getting the status of the query, error_info contain the cause of the error
			     	 (1, resultID sucessfully finished)
		'''	

		data = {'resultID': resultID}

		url = 'https://{}/rs/esm/v2/qryGetResults'.format(self.esmserver)

		try:
			r = requests.post(url + '?startPos=0&numRows=5000', data = json.dumps(data), headers=self.auth_header, verify=False)
		except requests.exceptios.ConnectionError:
			error_info = "Get query result - ESM connection Error"
			return(0, error_info)

		if r.status_code == 200:
			r = r.json()
			rows = r['rows']
			columns = r['columns']

			rows_values = [row['values'] for row in rows]
			columns_name = [column['name'] for column in columns]

			dataframe = pd.DataFrame(rows_values, columns=columns_name)
			return (1, dataframe)

		else:
			error_info = "Get query results for jobID %s unsucessful, Status error, Status Code: %d"%(resultID, r.status_code)
			return(0, error_info)	


class Utils():

	@classmethod
	def files_setup(self):
		logFolder = os.curdir + os.sep + 'files'

		if not os.path.exists(logFolder):
			os.makedirs(logFolder)

		today = date.today()
		yesterday = today - timedelta(1)

		today_string = today.strftime("%Y%m%d") + "esm.log"
		yesterday_string = yesterday.strftime("%Y%m%d") + "esm.log"

		files_to_maintain = [os.path.join(logFolder + os.sep, today_string), os.path.join(logFolder + os.sep, yesterday_string)]

		list_of_files = [os.path.join(logFolder + os.sep, f) for f in os.listdir(logFolder) if os.path.isfile(os.path.join(logFolder + os.sep, f))]
		files_to_delete = [f for f in list_of_files if f not in files_to_maintain]

		for f in files_to_delete:
			os.remove(f)

		return(0)


	@classmethod
	def get_output_file(self):
		logFolder = os.curdir + os.sep + 'files' + os.sep
		today = date.today()
		string = logFolder + today.strftime("%Y%m%d") + "esm.log"
		
		return string

	@classmethod
	def log_setup(self):
		''' Setting up the logger '''
		global logger    


		logger = logging.getLogger('myapp')

		logFolder = os.curdir + os.sep + 'log'
		if not os.path.exists(logFolder):
		    os.makedirs(logFolder)

		'''
		    Rotating log file with size of 5Mb.
		'''
		hdlr = RotatingFileHandler(logFile, mode='a', maxBytes=(4*1000*1000), backupCount=10, encoding=None, delay=0)

		'''
		    Value        Type of interval
		    's'            Seconds
		    'm'            Minutes
		    'h'            Hours
		    'd'            Days
		    'w0'-'w6'    Weekday (0=Monday)
		    'midnight'    Roll over at midnight

		    will rotate logs 3 days once

		hdlr = TimedRotatingFileHandler(logFile, when="d", interval=3, backupCount=100, encoding=None, delay=0) 
		'''
		formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
		hdlr.setFormatter(formatter)
		logger.addHandler(hdlr)
		logger.setLevel(logging.INFO)

		return (0)

def parseargs():
	'''
	Description: Function in charge of the CLI parameters
	Input:       No input
	Output:      Parsed arguments
	'''
	description = 'McAfee SIEM to Telefonica Sandas'
	prog = 'getevents.py'
	usage = '\ngetevents.py [-ip ESM_IP_Address] [-u ESM_Username] [-p ESM_Password]'
	epilog = 'Carlos Munoz (carlos_munozgarrido@mcafee.com)\n%(prog)s 1.0 (10/04/2019)'

	parser = argparse.ArgumentParser(epilog=epilog, usage=usage, prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter)

	atd_group = parser.add_argument_group("McAfee SIEM login parameters")

	arg_help = "Ip address of ESM Server"
	atd_group.add_argument('-ip', required=True, default = "", action='store', dest='esm_ipaddress', help=arg_help, metavar= "")

	arg_help = "Username for ESM"
	atd_group.add_argument('-u', required=True, default = "", action='store', dest='esm_username', help=arg_help, metavar="")

	arg_help = "Password for ESM"
	atd_group.add_argument('-p', required=True, default = "", action='store', dest='esm_password', help=arg_help, metavar="")

	parser.add_argument('--version', action='version', version='Carlos Munoz (carlos?munozgarrido@mcafee.com)\n%(prog)s 1.0 (10/04/2019)')

	return parser.parse_args()

def main():

	# get script parameters
	option = parseargs()

	# logger initialization
	Utils.log_setup()
	logger.info('Logger initialized')

	# Creación de carpeta para el almacenamiento de los logs
	Utils.files_setup()
	print("Debug - File maintenance done")
	logger.info("File maintenance done")

	esm = McAfee_SIEM(option.esm_ipaddress)
	status, info = esm.connect(option.esm_username, option.esm_password)

	if status:
		print("Debug - Connection stablished")
		logger.info(info)
	else:
		print("Debug - Error while connecting")
		logger.error(info)
		sys.exit()

	last_time_query = time.time()
	last_time_query = last_time_query - QUERY_DELAY # So the first time the application queries ESM
	last_time_heartbeat = time.time()

	processed_correlatedID = []

	try:
		while True:
			current_time = time.time()
			time.sleep(1)
			if current_time - last_time_query > QUERY_DELAY:
				last_time_query = current_time
				# Executing query against the REST API

				# I want to filter the query by the Correlation Engine
				# As there are different Correlation Engine (On the receiver, ACE, Risk, etc.)
				# I have obtained the following values filtering by Device Type IP on the ESM
				#  - Ace Correlation --> 380
				#  - Correlation Enfine --> 47
				#  - McAfee Advanced Correlation engine --> 335
				#  - Ace Risk Manager --> 335
				filters = {'field':'DSID', 'operator': 'IN', 'values':'47, 380, 335, 345'} 

				fields  = ['FirstTime','LastTime','ThirdPartyType.Name','DSID','IPSID','AlertID',\
		          		   'Rule_NDSNormSigID.msg','Rule.msg','Rule_Name','Action.Name','EventCount','Severity','AvgSeverity',\
		          		   'SrcIP','SrcPort','DstIP','DstPort','Protocol',\
		          		   'UserIDSrc','UserIDDst','Message_Text','ID','GeoLoc_ASNGeoDst.Msg','GeoLoc_ASNGeoSrc.Msg']

				status, info = esm.esm_query(filters=filters, fields=fields)


				if not status:
					print("Debug - ESM query unsucessfull")
					logger.error(info)
					raise KeyboardInterrupt


				print("Debug - ESM query sucessful")
				resultID = info
				logger.info("ESM queried sucessfully, jobID: %s"%resultID)

				status = False
				while not status:
					print("Debug - Waiting 10 seconds before to check if the resultId is ready")
					time.sleep(10)
					status, info = esm.query_status(resultID)
					if status == 0:
						print("Debug - Query status error")
						logger.error(info)
						raise KeyboardInterrupt
					elif status == 2:
						print("Debug - Query status not yet ready")
						logger.info(info)
						continue
					else: # Query status is == 1 so is finished and complete
						print("Debug - Query status ready")
						logger.info(info)

				status, info = esm.get_query_results(resultID)
				if status == 0:
					print("Debug - get query results error")
					logger.error(info)
					raise KeyboardInterrupt

				print("Debug - Get query results for jobID %s sucessfull"%resultID)
				logger.info("Get query results for jobID %s sucessfull"%resultID)
				dataframe = info

				if len(dataframe) == 0:
					# empty dataframe
					print("Debug - No new events to be written")
					logger.info("No new events to be written")
				else:
					# Creamos una nueva columna en el dataframe mezclando los valores Alert.IPSID y AlertID.
					dataframe["Identificator"] = dataframe["Alert.IPSID"] + "|" + dataframe["Alert.AlertID"]
					# El comando ~dataframe.Identificator.isin(processed_correlatedID) genera un boolean dataframe 
					# poniendo a True todo lo que no esta en la lista processed_correlatedID y a False lo que esta
					# en la lista. Si se le quita el caracter ~ pondrá a True todo lo que está en la lista y a 
					# False todo lo que no está
					dataframe = dataframe[~dataframe.Identificator.isin(processed_correlatedID)]

					filename = Utils.get_output_file()
					f = open(filename,"a+")

					for index, row in dataframe.iterrows():						
						correlated_event_ID = row["Identificator"]
						print("Debug - Writting event: %s in %s"%(correlated_event_ID, filename))
						logger.info("Writting event: %s in %s"%(correlated_event_ID, filename))

						processed_correlatedID.append(correlated_event_ID)
						
						fields  = ['Alert.FirstTime', 'Alert.LastTime', 'ThirdPartyType.Name',
							       'Alert.DSID', 'Alert.IPSID', 'Alert.AlertID', 'Rule_NDSNormSigID.msg',
							       'Rule.msg', 'Alert.65616', 'Action.Name', 'Alert.EventCount',
							       'Alert.Severity', 'Alert.AvgSeverity', 'Alert.SrcIP', 'Alert.SrcPort',
							       'Alert.DstIP', 'Alert.DstPort', 'Alert.Protocol', 'Alert.BIN(7)',
							       'Alert.BIN(6)', 'Alert.4259842', 'Rule.ID', 'GeoLoc_ASNGeoDst.Msg',
							       'GeoLoc_ASNGeoSrc.Msg']
						string = ""
						for field in fields:
							string = string + row[field] + ","

						string = string[:-1] + "\n"
						f.write(string)

					f.close()

				
			elif current_time - last_time_heartbeat > HEARBEAT:
				last_time_heartbeat = current_time
				status, info = esm.keepAlive()				

				if status:
					print("Debug - Heartbeat Sucessful")
					logger.info(info)
				else:
					print("Debug - Heartbeat unsucessfull")
					logger.error(info)
					raise KeyboardInterrupt


	except KeyboardInterrupt:
		logger.info('Keyboard interrupt received. Disconnecting from SIEM')
		status, info = esm.disconnect()
		if status:
			print("Debug - Disconnection sucessful")
			logger.info(info)
		else:
			print("Debug - Error while disconnecting")
			logger.error(info)

if __name__ == "__main__":
	main()