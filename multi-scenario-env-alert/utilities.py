class utilities:

    def __init__(self):
        import string
        import logging as logging
        import sys as sys
        
        self.logging = logging
        self.credentials = None
        self.sys = sys
        
        #read setup file
        self.setup_file_path = './docs/setup.json'
        self.get_setup()
        
    # ################################################
    # Import related functions
    # ################################################

    def import_library(self, library_package, library_names = None):
        try:
            if library_names is None:
                self.logging.info("Importing %s library" % library_package)
                return __import__(library_package)
            else:
                self.logging.info("Importing %s library from %s" %(' and '.join(library_names),library_package))
                return __import__(name=library_package,fromlist=library_names)
        except ImportError:
            raise ImportError('Library was not found: %s' %(library_package))
            
    # ################################################
    # Authorization & Authentication related functions
    # ################################################

    def get_credentials(self):
        try:
            j = self.import_library('json')
            sp= self.import_library('azure.common.credentials',['ServicePrincipalCredentials'])
            #import_library('msrestazure.azure_active_directory','MSIAuthentication')
            #self.import_libraries('msrestazure.azure_active_directory','MSIAuthentication')

            with open('./secrets/secrets.json','r') as data_file:
                data = j.load(data_file)

            TENANT_ID = data['keyvault']['tenant_id']
            # Your Service Principal App ID
            CLIENT = data['keyvault']['client']
            # Your Service Principal Password
            KEY = data['keyvault']['key']

            credentials = sp.ServicePrincipalCredentials(client_id = CLIENT, secret = KEY, tenant = TENANT_ID)
            # As of this time this article was written (Feburary 2018) a system assigned identity could not be used from a development/local
            # environment while using MSIAuthentication. When it's supported, you may enable below line instead of the above lines
            # credentials = MSIAuthentication()
            return credentials
        except Exception as e:
            self.logging.error("could not get the credentials: %s" %(e))
            self.credentials = None

    def get_secret_value(self,secret_name):
        #secret_name maps to the EnvironmentName in scenarios.json
        kvc = self.import_library('azure.keyvault',['KeyVaultClient'])
        self.import_library('azure.keyvault',['KeyVaultAuthentication'])

        if(self.credentials is None):
            self.credentials = self.get_credentials() 
        key_vault_client = kvc.KeyVaultClient(self.credentials)

        # Your KeyVault URL, name of your secret, the version of the secret. Empty string for latest. Your provided enviroment needs to match the secret name
        return key_vault_client.get_secret(self.key_vault_uri, secret_name,"").value

    # ################################################
    # Sql connectivity related functions
    # ################################################

    def get_connection(self,conn_string):
        psycopg2 = self.import_library('psycopg2')
        try:
            return psycopg2.connect(conn_string)
        except Exception as e:
            self.logging.error("could not establish connection: %s" %(e))

    def get_cursor(self,conn):
        cursor = conn.cursor()
        return cursor

    def commit_close(self,conn,cursor):

        # Cleanup
        conn.commit()
        cursor.close()
        conn.close()

    def rollback_close(self,conn,cursor):

        # Cleanup
        conn.rollback()
        cursor.close()
        conn.close()


    # ################################################
    # Alerting scenario related functions
    # ################################################

    def get_scenario(self,scenario=None):
        os = self.import_library('os')
        json = self.import_library('json')
        try:
            self.logging.info("Current working directory is: %s" %os.getcwd())
            self.logging.info("Reading the scenario specifics")
            
            with open(self.scenario_file_path,'r') as data_file:
                data = json.load(data_file)

            #read the json entry matching the scenario into a list
            if(scenario is None):
                return data
            else:
                return [v[0] for k,v in data.items() if k == '%s'%(scenario)]

        except ValueError as e:
            self.logging.error("Required arguments not passed: %s" %(e))
            #self.sendMail(ADMIN,SENDER,"Cron job missing arguments","Please review your cron job for missing arguments. Expecting scenario ....py scenarioFilePath in order")

        except Exception as e:
            self.logging.error("Error reading scenario file: %s" %(e))
            #self.sendMail(ADMIN,SENDER,"Cron job cannot start %s scenario" %(scenario),"There is an issue with loading the json section for this scenario. Please ensure json is well-formed.")

    # ################################################
    # Read setup.json file
    # ################################################

    def get_setup(self):
        os = self.import_library('os')
        json = self.import_library('json')
        try:
            self.logging.info("Current working directory is: %s" %os.getcwd())
            self.logging.info("Reading setup file")
            
            with open(self.setup_file_path,'r') as data_file:
                data = json.load(data_file)

            self.admin = data['admin_email']
            self.sender = data['sender_email']
            self.scenarios_to_run = json.loads(data['scenarios_to_run'])['scenarios']
            self.scenario_file_path = data['scenario_file_path']
            self.key_vault_uri = data['key_vault_uri']
            self.smtpserver = data['smtp_server']
            self.smtpport = data['smtp_port']
            self.sender_secret_name = data['sender_secret_name']

        except ValueError as e:
            self.logging.error("Required arguments not passed: %s" %(e))
            #self.sendMail(ADMIN,SENDER,"Cron job missing arguments","Please review your cron job for missing arguments. Expecting scenario ....py scenarioFilePath in order")

        except Exception as e:
            self.logging.error("Error reading scenario file: %s" %(e))
            #self.sendMail(ADMIN,SENDER,"Cron job cannot start %s scenario" %(scenario),"There is an issue with loading the json section for this scenario. Please ensure json is well-formed.")


    # ################################################
    # Email related functions
    # ################################################

    def send_my_mail(self,to, fr, subject, text, files={},server='smtp.office365.com'):
        slib = self.import_library('smtplib')
        self.import_library('email')
        #self.import_library('email.mime')
        
        try:
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from email.mime.text import MIMEText
            from email import encoders
            from email.utils import formatdate  
            msg = MIMEMultipart()
            msg['From'] = fr
            msg['To'] = to
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = subject
            msg.attach( MIMEText(text) )

            for filekey,filevalue in files.items():
                part = MIMEBase('application', "octet-stream")
                part.set_payload(filevalue)
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="%s"'% filekey)
                msg.attach(part)

            smtp = slib.SMTP(self.smtpserver,self.smtpport)
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(self.sender,self.get_secret_value(self.sender_secret_name))
            smtp.sendmail(fr, to, msg.as_string() )
            smtp.close()
            self.logging.info("Successfully sent email")

        except slib.SMTPException as e:
            self.logging.error("Unable to send email: %s" %(e))
        except Exception as ex:
            self.logging.error("An error occurred: %s" %(ex))