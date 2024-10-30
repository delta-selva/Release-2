import json
import secrets
import string
import sys, os
import base64
import sqlite3
# import datetime
import uuid
import json
import os
import shutil
import hashlib
import secrets
import jwt
import pytz
from datetime import datetime, timedelta
DB_FOLDER = "./apps/DB/"
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')



class Model:

    def __init__(self):
        self.db_path = DB_FOLDER + 'agents.db'
        self.create_agents_db()
        self.create_file_uploads_db()
        self.create_tables()
        self.secret_key = secrets.token_hex(32)
        self.UPLOAD_DIRECTORY = "./Reports/"
        self.scan_directory_path = None  

    def create_tables(self):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Create engineers table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS engineers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_name TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        phone_number TEXT,
                        eng_id TEXT, 
                        position TEXT,
                        company_name TEXT,
                        projects TEXT DEFAULT NULL,
                        current_user TEXT NOT NULL
                    )
                ''')

                # Create projects table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS projects (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_name TEXT NOT NULL UNIQUE,
                        authorizer TEXT NOT NULL,
                        reporting_manager TEXT NOT NULL,
                        created_date DATETIME NOT NULL,
                        project_type TEXT NOT NULL,
                        progress TEXT NOT NULL DEFAULT 'To-Do',
                        dut TEXT NOT NULL,
                        current_user TEXT NOT NULL  -- Corrected line
                    )
                ''')

                # Create test_engineers table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS test_engineers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        engineer_name TEXT NOT NULL
                    )
                ''')

                # Create project_test_engineers (junction table)
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS project_test_engineers (
                        project_id INTEGER,
                        engineer_id INTEGER,
                        PRIMARY KEY (project_id, engineer_id),
                        FOREIGN KEY (project_id) REFERENCES projects (id),
                        FOREIGN KEY (engineer_id) REFERENCES test_engineers (id)
                    )
                ''')

                # Create Project_Type table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS Project_Type (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type_name TEXT NOT NULL UNIQUE
                    )
                ''')
                
                # cur.execute('DROP TABLE IF EXISTS subtypes')
                # Create subtypes table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS subtypes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        subtype_name TEXT NOT NULL UNIQUE,
                        Project_Type_id INTEGER NOT NULL,
                        FOREIGN KEY (Project_Type_id) REFERENCES Project_Type (id)
                    )
                ''')

                # Load data from config.json
                with open('config.json', 'r') as json_file:
                    config_data = json.load(json_file)

                # Insert project types
                cur.executemany('INSERT OR IGNORE INTO Project_Type (type_name) VALUES (?)',
                                [(ptype,) for ptype in config_data['project_types']])

                # Insert subtypes
                for subtype in config_data['subtypes']:
                    cur.execute('''
                        INSERT OR IGNORE INTO subtypes (subtype_name, Project_Type_id)
                        VALUES (?, ?)
                    ''', (subtype['subtype_name'], subtype['project_type_id']))

                # Commit the transaction
                con.commit()

                # print("Tables created successfully.")
        except sqlite3.Error as e:
            print(f"An error occurred while creating tables: {e}")

    def create_agents_db(self):
        """Create the agents and ssh_credentials tables if they do not exist."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                
                # Create the agents table
                # cur.execute('DROP TABLE IF EXISTS agents')
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS agents (
                        id TEXT PRIMARY KEY,
                        current_user TEXT NOT NULL,
                        api_key TEXT NOT NULL,
                        token TEXT NOT NULL,
                        token_expiry DATETIME NOT NULL,
                        agent_name TEXT UNIQUE NOT NULL,
                        api_validate BOOLEAN NOT NULL DEFAULT 0
                    )
                ''')

                # Create the ssh_credentials table
                # cur.execute('DROP TABLE IF EXISTS ssh_credentials')
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_credentials (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Add a primary key column
                            project_id INTEGER NOT NULL,            -- Keep project_id as a regular column
                            ssh_username TEXT NOT NULL,
                            ssh_password TEXT NOT NULL,
                            FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                        )
                    ''')

                # Create the ssh_credentials table
                # cur.execute('DROP TABLE IF EXISTS scan')
                # cur.execute('DROP TABLE IF EXISTS scan')
                # cur.execute('DROP TABLE IF EXISTS scan_data')
                # Create scan table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS scan (
                        id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        subtype_name TEXT NOT NULL,
                        repo_dir TEXT,
                        current_user TEXT,
                        status TEXT DEFAULT 'Progress',
                        FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
                    )
                ''')
                
                cur.execute('''
                CREATE TABLE IF NOT EXISTS scan_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,  -- Foreign Key to link back to scan table
                    agent_name TEXT NOT NULL,
                    upload_date DATETIME NOT NULL,
                    upload_time DATETIME NOT NULL,
                    
                    
                    FOREIGN KEY(scan_id) REFERENCES scan(id) ON DELETE CASCADE
                )
                ''')
               
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS EUTConfiguration (
                        id TEXT PRIMARY KEY,
                        customer TEXT,
                        model_no TEXT,
                        product_name TEXT,
                        manufacturer TEXT,
                        serial_no TEXT,
                        software_version TEXT,
                        hardware_version TEXT,
                        product_no TEXT UNIQUE,
                        front_img BLOB, 
                        side_img BLOB, 
                        port_img BLOB
                    )
                ''')
             
                            
                con.commit()
                
        
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS agent_engineer_id (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        engineer_name TEXT NOT NULL
                    )
                ''')

                cur.execute('''
                    CREATE TABLE IF NOT EXISTS agent_engineers (
                    agent_id TEXT,
                    engineer_id INTEGER,
                    FOREIGN KEY (agent_id) REFERENCES agents (id),
                    FOREIGN KEY (engineer_id) REFERENCES agent_engineer_id (id),
                    PRIMARY KEY (agent_id, engineer_id)
                )
                ''')              
            
                con.commit()
        except sqlite3.Error as e:
            print(f"An error occurred while creating the agents table: {e}")

    def generate_api_key(self, agent_name):
        """Generate an API key based on the agent name and a random salt."""
        salt = uuid.uuid4().hex
        return hashlib.sha256(f"{agent_name}{salt}".encode()).hexdigest()

    def generate_token(self, agent_name):
        """Generate a JWT token for the agent with a short expiry."""
        try:
            time_value_str = os.getenv('TIME')  
            if not time_value_str:
                raise ValueError("TIME environment variable is not set.")
            
            time_value = int(time_value_str.strip())

            current_time = datetime.now()
            expiry_time = current_time + timedelta(minutes=time_value)

            payload = {
                'agent_name': agent_name,
                'exp': expiry_time
            }
            
            token = jwt.encode(payload, self.secret_key, algorithm='HS256')
            return token, expiry_time
        except Exception as e:
            print(f"Error generating token: {e}")
            return None, None

    def create_agent(self, agent_name, current_user, engineer_name):
        """Add a new agent to the database, generate tokens, and associate SSH credentials."""
        try:
         
            # Generate UUID and create the directory
            agent_uuid = uuid.uuid4().hex
            # repo_dir = os.path.join(self.UPLOAD_DIRECTORY, str(current_user))

            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Check if the agent already exists
                cur.execute('SELECT * FROM agents WHERE agent_name = ?', (agent_name,))
                existing_agent = cur.fetchone()

                if existing_agent:
                    return {"error": "Agent already exists"}, 400

                # Generate API key and token
                api_key = self.generate_api_key(agent_name)
                token, token_expiry = self.generate_token(agent_name)

                # Insert the new agent into the agents table
                cur.execute('''
                    INSERT INTO agents (id, current_user, api_key, token, token_expiry, agent_name, api_validate) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (agent_uuid, str(current_user), api_key, token, token_expiry, agent_name, 0))  # 0 = false for validate

          
                # Insert and associate the engineer (if provided)
                

                if engineer_name:  # Ensure there's a valid engineer name
                    engineer_name = engineer_name.strip()
                    # Check if the engineer already exists
                    cur.execute('SELECT id FROM agent_engineer_id WHERE engineer_name = ?', (engineer_name,))
                    result = cur.fetchone()

                    if result:  # If the engineer exists
                        engineer_id = result[0]
                        # print(f"Engineer '{engineer_name}' exists with ID: {engineer_id}")
                    else:  # If the engineer doesn't exist, insert a new record
                        cur.execute('''
                            INSERT INTO agent_engineer_id (engineer_name)
                            VALUES (?)
                        ''', (engineer_name,))
                        engineer_id = cur.lastrowid
                        # print(f"Inserted new engineer '{engineer_name}' with ID: {engineer_id}")

                    # Associate engineer with the agent in the junction table
                    cur.execute('''
                        INSERT INTO agent_engineers (agent_id, engineer_id)
                        VALUES (?, ?)
                    ''', (agent_uuid, engineer_id))
                    # print(f"Associated engineer ID {engineer_id} with agent ID {agent_uuid}")

                con.commit()
                return {"message": "Agent created", "api_key": api_key, "token": token}, 201

        except sqlite3.IntegrityError as e:
            print(f"Integrity error occurred: {e}")
            return {"error": "Integrity error"}, 400
        except sqlite3.Error as e:
            print(f"An error occurred while creating agent: {e}")
            return {"error": "Failed to create agent"}, 500
        except json.JSONDecodeError as e:
            print(f"Error reading the config file: {e}")
            return {"error": "Failed to read config"}, 500
        except FileNotFoundError:
            print("Config file not found.")
            return {"error": "Config file not found"}, 500

    def validate_api_key(self, api_key=None, token=None):
        """Validate the provided API key or token and return the associated current_user."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Validate using token if provided
                if token:
                    cur.execute('SELECT * FROM agents WHERE token = ?', (token,))
                    agent = cur.fetchone()
                    # print("agent token: ", agent)

                    if agent:
                        return {
                            "message": "Token is valid",
                            "current_user": agent[1],
                            "agent_name": agent[5],
                            "token": token
                        }, 200
                    return {"error": "Invalid token"}, 401

                # Validate using API key if provided
                elif api_key:
                    cur.execute('SELECT * FROM agents WHERE api_key = ?', (api_key,))
                    agent = cur.fetchone()
                    # print("agent: ", agent)

                    if agent:
                        api_validate = agent[2]  # Assuming api_validate is at index 7
                        # print("api_validate :", api_validate)
                        
                        # Check if API key has already been validated
                        if api_validate == 1:
                            return {"error": "API key has already been validated and cannot be reused"}, 403

                        # Optionally, update API validation status to 1 if it's not already validated
                        self.update_api_validation_status(api_key)

                        # Retrieve the token for the agent
                        token = agent[3]  # Assuming the token is at index 3
                        return {
                            "message": "API key is valid",
                            "current_user": agent[1],
                            "agent_name": agent[6],
                            "token": token
                        }, 200
                    
                    return {"error": "Invalid API key"}, 401  # API key does not exist

                # Return an error if neither token nor API key is provided
                return {"error": "API key or token is required"}, 400

        except Exception as e:
            print(f"Error validating API key or token: {e}")
            return {"error": "Validation failed"}, 500

    def update_api_validation_status(self, api_key):
        """Update the api_validate field to 1 after successful token retrieval."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('UPDATE agents SET api_validate = 1 WHERE api_key = ?', (api_key,))
                con.commit()
        except Exception as e:
            print(f"Error updating API validation status: {e}")
           
    def delete_agent(self, agent_name, current_user):
        """Delete an agent from the database, associated engineers, and remove the corresponding directory."""
        try:
            current_user_str = str(current_user)
            
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Find the agent in the agents table
                cur.execute('SELECT * FROM agents WHERE agent_name = ? AND current_user = ?', (agent_name, current_user_str))
                columns = [description[0] for description in cur.description]
                agent = cur.fetchone()

                if not agent:
                    return {"error": "Agent not found or unauthorized"}, 404

                # Get agent UUID and repo directory
              
                agent_id_index = columns.index('id')
                agent_id = agent[agent_id_index]
            

                # Step 1: Delete associated engineers from agent_engineers table
                cur.execute('SELECT engineer_id FROM agent_engineers WHERE agent_id = ?', (agent_id,))
                engineer_ids = cur.fetchall()

                if engineer_ids:
                    # Delete from agent_engineer_id for each associated engineer
                    for engineer_id in engineer_ids:
                        cur.execute('DELETE FROM agent_engineer_id WHERE id = ?', (engineer_id[0],))
                    
                    # Delete associations from agent_engineers
                    cur.execute('DELETE FROM agent_engineers WHERE agent_id = ?', (agent_id,))

                # Step 2: Delete the agent from the agents table
                cur.execute('DELETE FROM agents WHERE id = ?', (agent_id,))

                # Step 3: Commit changes to the database
                con.commit()

               
                return {"message": "Agent and associated engineers deleted"}, 200
        except Exception as e:
            print(f"Error deleting agent: {e}")
            return {"error": "Failed to delete agent"}, 500
        
    def list_agents(self, current_user):
        """List all agents and their associated engineers for the current user."""
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                
                # SQL query to fetch agents and their associated engineers
                cur.execute('''
                    SELECT 
                        a.agent_name, 
                        GROUP_CONCAT(e.engineer_name, ", ") AS engineers
                    FROM 
                        agents a
                    LEFT JOIN 
                        agent_engineers ae ON a.id = ae.agent_id
                    LEFT JOIN 
                        agent_engineer_id e ON ae.engineer_id = e.id
                    WHERE 
                        a.current_user = ?
                    GROUP BY 
                        a.agent_name
                ''', (current_user_str,))
                
                agents_with_engineers = cur.fetchall()
                # print("agents_with_engineers", agents_with_engineers)  # Debugging line
                
                # Return the data in a list of dictionaries
                return [{'agent_name': row[0], 'engineers': row[1]} for row in agents_with_engineers]
        except Exception as e:
            print(f"Error retrieving agents: {e}")
            return []

    def get_agents_count(self, current_user):
        """List all agents associated with the current user and return the count."""
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                
                # Fetch agent names
                cur.execute('SELECT agent_name FROM agents WHERE current_user = ?', (current_user_str,))
                agents = cur.fetchall()
                agent_names = [agent[0] for agent in agents]
                
                # Get the count of agents
                agent_count = len(agent_names)
                
                # Return both agent names and count
                return {
                    
                    'agent_count': agent_count
                }
        except Exception as e:
            print(f"Error listing agents: {e}")
            return {
                
                'agent_count': 0
            }

    def update_token_for_agent(self, agent_name):
        """Update the token for an agent."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                
                token, token_expiry = self.generate_token(agent_name)
                cur.execute('UPDATE agents SET token = ?, token_expiry = ? WHERE agent_name = ?', (token, token_expiry, agent_name))
                con.commit()
                return {"message": "Token updated", "new_token": token, "token_expiry": token_expiry}
        except Exception as e:
            print(f"Error updating token: {e}")
            return {"error": "Failed to update token"}
        
    def get_agent_info_by_token(self, client_uid):
        """Retrieve agent information by token."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('SELECT agent_name, current_user FROM agents WHERE token = ?', (client_uid,))
                agent = cur.fetchone()
                # print(agent)
                if agent:
                    return {
                        "agent_name": agent[0],
                        "username": agent[1]
                    }
                # print("agent",agent)
                return None
        except Exception as e:
            print(f"Error retrieving agent info: {e}")
            return None
           
    def create_scan_directory(self, client_uid, scan_id):
        """Create the directory structure for storing scan results based on the token."""
        try:
            # print("client_uid", client_uid, scan_id)
            agent_info = self.get_agent_info_by_token(client_uid)
            # print("agent_info", agent_info)
            
            if not agent_info:
                raise ValueError("Token not found or does not match any agent")

            repo_dir = agent_info['repo_dir']
            # print("repo_dir", repo_dir)
            scan_directory = os.path.join(repo_dir, scan_id)
            # print("scan_directory", scan_directory)
            
            if not os.path.exists(scan_directory):
                os.makedirs(scan_directory)
            
            self.scan_directory_path = scan_directory
            return {"scan_directory": scan_directory, "agent_name": agent_info['agent_name'], "username": agent_info['username']}
        except Exception as e:
            print(f"Error creating scan directory: {e}")
            return None
        
    def create_scan_id(self, scan_id, project_name, test_case):
        """Create a scan entry in the database and return the scan_id along with SSH credentials."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Step 1: Get the project type, project ID, and current_user from the projects table
                cur.execute("SELECT project_type, id, current_user FROM projects WHERE project_name = ?", (project_name,))
                project_row = cur.fetchone()

                if not project_row:
                    return None  # Project not found

                project_type = project_row[0]  # First element is project_type
                project_id = project_row[1]    # Second element is project_id
                current_user = project_row[2]  # Third element is current_user

                # Step 2: Get the project type ID from Project_Type table
                cur.execute("SELECT id FROM Project_Type WHERE type_name = ?", (project_type,))
                project_type_row = cur.fetchone()

                if not project_type_row:
                    return {"error": "Project type not found"}
                
                project_type_id = project_type_row[0]  # Accessing the ID of the project type

                # Step 3: Check if the test_case exists in the subtypes table
                cur.execute("SELECT id FROM subtypes WHERE subtype_name = ? AND Project_Type_id = ?", (test_case, project_type_id))
                subtype_row = cur.fetchone()

                if not subtype_row:
                    return {"error": "Testcase name is not there in the project"}  # Test case not found

                # Step 4: Create the repo_dir using the current_user from the project
                repo_dir = os.path.join(self.UPLOAD_DIRECTORY, str(current_user), str(project_id), scan_id)  # Create the repo_dir
                # print(f"Constructed repo_dir: {repo_dir}")


                # Create the repo_dir folders if they don't exist
                try:
                    os.makedirs(repo_dir, exist_ok=True)  # Create the directory, including any necessary parent directories
                    # print(f"Created directory: {repo_dir}")
                except Exception as e:
                    print(f"Failed to create directory {repo_dir}: {e}")


                # Step 5: Insert the new scan into the scan table
                cur.execute(
                    "INSERT INTO scan (id, project_id, subtype_name, repo_dir, current_user) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, project_id, test_case, repo_dir, current_user)  # Add current_user to the values being inserted
                )

                # Step 6: Retrieve SSH credentials using the project_id
                cur.execute("SELECT ssh_username, ssh_password FROM ssh_credentials WHERE project_id = ?", (project_id,))
                ssh_credentials_row = cur.fetchone()

                if not ssh_credentials_row:
                    return None  # SSH credentials not found

                ssh_username = ssh_credentials_row[0]  # First element is ssh_username
                ssh_password = ssh_credentials_row[1]  # Second element is ssh_password

            con.commit()

            # Return the scan ID, repo_dir, SSH username, and SSH password
            return {
                'scan_id': scan_id,
                'repo_dir': repo_dir,
                'ssh_username': ssh_username,
                'ssh_password': ssh_password,
                'project_type' : project_type
            }

        except sqlite3.IntegrityError as e:
            print(f"Integrity error occurred: {e}")
            return {"error": "Database integrity error"}  # or raise the error depending on how you want to handle it

        except Exception as e:
            print(f"An error occurred: {e}")
            return {"error": "An unexpected error occurred"}
    
    def get_dut_details(self, project_name):
        """Retrieve DUT details from EUTConfiguration using the product_no from the project."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Step 1: Get the product_no associated with the project
                cur.execute("SELECT dut FROM projects WHERE project_name = ?", (project_name,))
                project_row = cur.fetchone()

                if not project_row:
                    return {"error": "Project not found"}

                product_no = project_row[0]  # Get the product_no from the project

                # Step 2: Fetch the DUT details from EUTConfiguration using the product_no
                cur.execute("SELECT customer, model_no, product_name, manufacturer, serial_no, software_version, hardware_version,product_no, front_img, side_img, port_img FROM EUTConfiguration WHERE product_no = ?", (product_no,))
                eut_row = cur.fetchone()

                if not eut_row:
                    return {"error": "DUT details not found for the provided product_no"}

                # Return the DUT details as a dictionary
                return {
                    "customer": eut_row[0],
                    "model_no": eut_row[1],
                    "product_name": eut_row[2],
                    "manufacturer": eut_row[3],
                    "serial_no": eut_row[4],
                    "software_version": eut_row[5],
                    "hardware_version": eut_row[6],
                    "product_no": eut_row[7],
                    "front_img": base64.b64encode(eut_row[8]).decode('utf-8') if eut_row[8] else None, 
                    "side_img": base64.b64encode(eut_row[9]).decode('utf-8') if eut_row[9] else None, 
                    "port_img": base64.b64encode(eut_row[10]).decode('utf-8') if eut_row[10] else None  
         
                }

        except sqlite3.Error as e:
            print(f"Database error occurred: {e}")
            return {"error": "Database error"}
        except Exception as e:
            print(f"An error occurred: {e}")
            return {"error": "An unexpected error occurred"}


       
    def handle_file_upload(self, json_file, pcap_file, upload_folder):
        """Handle the file upload and save them to the server."""
        try:
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            json_file_path = os.path.join(upload_folder, json_file.filename)
            pcap_file_path = os.path.join(upload_folder, pcap_file.filename)

            if not self.save_file(json_file, json_file_path):
                return {"error": "Failed to save JSON file"}, 500
            
            if not self.save_file(pcap_file, pcap_file_path):
                return {"error": "Failed to save PCAP file"}, 500
            
            return {"message": "Files uploaded successfully"}, 200
        except Exception as e:
            print(f"Error handling file upload: {e}")
            return {"error": "Error handling file upload"}, 500
        
    def save_file(self, file, path):
        """Save a file to the specified path."""
        try:
            file.save(path)
            return True
        except Exception as e:
            print(f"Error saving file: {e}")
            return False
        
    def store_metadata(self, agent_name,scan_id):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                # Get the current date and format it as 'YYYY-MM-DD'
                upload_date = datetime.now().strftime('%d-%m-%Y')
                # Get the current time and format it as 'HH:MM AM/PM'
                upload_time = datetime.now().strftime('%I:%M %p')
                # print(f"Formatted time: {upload_time}")  # Ensure time is formatted correctly
                # 
                # Insert metadata into the table
                cur.execute("""
                    INSERT INTO scan_data (scan_id,agent_name, upload_date,  upload_time)
                    VALUES (?, ?, ?, ?)
                """, (scan_id,agent_name, upload_date, upload_time))

                # Update the status to 'done' in the scan table for the related scan_id
                cur.execute("""
                    UPDATE scan
                    SET status = 'Done'
                    WHERE id = ?
                """, (scan_id,))

                con.commit()
                # print("Metadata stored successfully.")
        except Exception as e:
            print(f"Error storing metadata: {e}")

    def create_file_uploads_db(self):
        """Create the file_uploads table if it does not exist."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                # cur.execute('DROP TABLE IF EXISTS file_uploads')
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS file_uploads (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_name TEXT NOT NULL,
                        username TEXT NOT NULL,
                        test_case TEXT NOT NULL,
                        report_path TEXT NOT NULL,
                        upload_date DATETIME NOT NULL,
                        upload_Time DATETIME NOT NULL,
                        dut TEXT NOT NULL
                    )
                ''')
                con.commit()
                # print("file_uploads table created successfully.")
        except sqlite3.Error as e:
            print(f"An error occurred while creating the file_uploads table: {e}")

    def get_report_by_agentname(self, id):
        """Fetch file uploads by id."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('SELECT * FROM file_uploads WHERE id = ?', (id,))
                uploads = cur.fetchall()
                # print("1584 uploads", uploads)
                return uploads
        except sqlite3.Error as e:
            print(f"An error occurred while fetching file uploads for agent '{id}': {e}")
            return []
    
    def list_projects(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch projects associated with the current user
                cur.execute('''
                    SELECT p.id, p.project_name, p.authorizer, p.reporting_manager, p.created_date, 
                        p.project_type, p.progress, p.dut, 
                        GROUP_CONCAT(e.engineer_name) as engineer_names
                    FROM projects p
                    LEFT JOIN project_test_engineers pe ON p.id = pe.project_id
                    LEFT JOIN test_engineers e ON pe.engineer_id = e.id
                    WHERE p.current_user = ?  -- Filter by current user
                    GROUP BY p.id
                ''', (current_user_str,))  # Correctly passing the current_user_str

                projects = cur.fetchall()

                # Convert to dictionary for easier handling in web apps
                project_list = []
                for project in projects:
                    project_list.append({
                        "id": project[0],
                        "project_name": project[1],
                        "authorizer": project[2],
                        "reporting_manager": project[3],
                        "created_date": project[4],
                        "project_type": project[5],
                        "progress": project[6],
                        "dut": project[7],
                        "engineer_names": project[8]  # Combined engineer names
                    })

                return project_list
        except sqlite3.Error as e:
            print(f"An error occurred while listing projects: {e}")
            return []
   
    def list_projects_index(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch only the last 5 projects based on id
                cur.execute('''
                SELECT p.id, p.project_name, p.authorizer, p.reporting_manager, p.created_date, 
                    p.project_type, p.progress, p.dut, 
                    GROUP_CONCAT(e.engineer_name) as engineer_names
                FROM projects p
                LEFT JOIN project_test_engineers pe ON p.id = pe.project_id
                LEFT JOIN test_engineers e ON pe.engineer_id = e.id
                WHERE p.current_user = ?  -- Filter by current_user
                GROUP BY p.id
                ORDER BY p.id DESC  -- Sort by the highest IDs (most recent projects)
                LIMIT 5  -- Limit to the last 5 projects
            ''', (current_user_str,))
                projects = cur.fetchall()

                # Convert to dictionary for easier handling in web apps
                project_list = []
                for project in projects:
                    project_list.append({
                        "id": project[0],
                        "project_name": project[1],
                        "authorizer": project[2],
                        "reporting_manager": project[3],
                        "created_date": project[4],
                        "project_type": project[5],
                        "progress": project[6],
                        "dut": project[7],
                        "engineer_names": project[8]  # Combined engineer names
                    })
                    
                return project_list
        except sqlite3.Error as e:
            print(f"An error occurred while listing projects: {e}")
            return []
 
    def get_project_id_by_name(self, project_name):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('''SELECT id FROM projects WHERE project_name = ?''', (project_name,))
                row = cur.fetchone()  # Fetch the first matching row
                return row[0] if row else None  # Return the ID or None if not found
        except Exception as e:
            print(f"Error retrieving project ID: {e}")
            return None  # Return None on error

    def add_project(self, db_path, project_details, engineer_names, current_user):
        try:
            # Load SSH credentials from config.json
            config_path = 'config.json'
            if not os.path.exists(config_path):
                # print("Config file not found.")
                return {"error": "Config file not found"}, 500
            
            with open(config_path, 'r') as config_file:
                config = json.load(config_file)
                ssh_username = config.get('ssh_credentials', {}).get('ssh_username')
                ssh_password = config.get('ssh_credentials', {}).get('ssh_password')

                # Debugging output for ssh_username and ssh_password
                # print(f"Loaded SSH Username: {ssh_username}, SSH Passsword: {ssh_password}")

                # Check if the SSH credentials are available
                if not ssh_username or not ssh_password:
                    # print("SSH username or password not found in config.")
                    return {"error": "SSH credentials not found in config"}, 400

            with sqlite3.connect(db_path) as con:
                cur = con.cursor()

                # Insert into the projects table, including current_user
                cur.execute('''
                    INSERT INTO projects (project_name, authorizer, reporting_manager, created_date, project_type, dut, current_user)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (*project_details, current_user.username))  # Include current_user.username

                project_id = cur.lastrowid  # Get the inserted project ID
                # print(f"Project created with ID: {project_id}")

                # Get the project_type from user input (assuming it's passed as the fifth element in project_details)
                project_type = project_details[4]  # Assuming project type is in the 5th position of project_details

                # Get project_type_id from Project_Type table
                cur.execute('''
                    SELECT id FROM Project_Type WHERE type_name = ?
                ''', (project_type,))
                project_type_id = cur.fetchone()
                if not project_type_id:
                    # print("Project type not found.")
                    return {"error": "Project type not found"}, 400
                project_type_id = project_type_id[0]

                # Get all subtype_names from subtypes table using project_type_id
                cur.execute('''
                    SELECT subtype_name FROM subtypes WHERE Project_Type_id = ?
                ''', (project_type_id,))
                subtype_names = cur.fetchall()  # Fetch all results

                if not subtype_names:
                    # print("No subtypes found for the given project type.")
                    return {"error": "No subtypes found for the given project type"}, 400

                # Insert SSH credentials for each subtype
                for subtype in subtype_names:
                    subtype_name = subtype[0]  # Extract the subtype name from the tuple

                    # Insert SSH credentials for the new project for each subtype
                    cur.execute('''
                        INSERT INTO ssh_credentials (project_id, ssh_username, ssh_password)
                        VALUES (?, ?, ?)
                    ''', (project_id, ssh_username, ssh_password))  # Include repo_dir in the insert
                    # print(f"Inserted SSH credentials for subtype: {subtype_name}")

                # Handle multiple engineers in the engineer_names list
                for engineer in engineer_names:
                    # print("engineers:", engineer)
                    engineers_list = engineer.split(",")  # Split string into list by commas
                    for single_engineer in engineers_list:
                        single_engineer = single_engineer.strip()  # Remove leading and trailing whitespace
                        # print("single_engineer :", single_engineer )
                        # Check if the engineer already exists
                        cur.execute('''
                            UPDATE engineers
                            SET projects = COALESCE(projects, '') || ?  -- Append new project to existing
                            WHERE employee_name = ?
                        ''', (f"{project_details[0]}, ", single_engineer))
                        if cur.rowcount == 0:
                            print(f"No engineer found with the name: {single_engineer}")
                # Commit the transaction after all inserts
                con.commit()
                # print("Project, engineers, and SSH credentials updated successfully.")
                return {"message": "Project added, SSH credentials created, and repo_dir updated."}, 201

        except sqlite3.IntegrityError as e:
            print(f"Integrity error occurred: {e}")
            raise
        except sqlite3.Error as e:
            print(f"An error occurred while adding project and engineers: {e}")
            raise
        except json.JSONDecodeError as e:
            print(f"Error reading the config file: {e}")
            return {"error": "Failed to read config"}, 500
        except FileNotFoundError:
            print("Config file not found.")
            return {"error": "Config file not found"}, 500
        
    def update_project(self, project_details, engineer_names):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Update the project details (including current_user)
                cur.execute('''
                    UPDATE projects
                    SET project_name = ?, authorizer = ?, reporting_manager = ?, project_type = ?, dut = ?, current_user = ?
                    WHERE id = ?
                ''', project_details[:-1] + (project_details[-1],))

                # Split engineer_names into a set, trimming whitespace
                new_engineers = {engineer.strip() for engineer in engineer_names[0].split(',')}
                # print("new_engineers:", new_engineers)

                # Fetch existing engineers associated with the project
                cur.execute('''
                    SELECT employee_name FROM engineers WHERE projects LIKE ?
                ''', (f'%{project_details[0]}%',))

                existing_engineers = {row[0] for row in cur.fetchall()}
                # print("existing_engineers:", existing_engineers)

                # Determine engineers to remove
                engineers_to_remove = existing_engineers - new_engineers
                # print("engineers_to_remove:", engineers_to_remove)

                # Remove the project name for engineers not in the new list
                for engineer in engineers_to_remove:
                    # Remove the specific project name and clean up commas
                    cur.execute('''
                        UPDATE engineers
                        SET projects = TRIM(REPLACE(
                            REPLACE(REPLACE(projects, ?, ''), ', ,', ','), 
                            ', ', ','
                        ))
                        WHERE employee_name = ?
                    ''', (f"{project_details[0]}, ", engineer))

                    # Clean up any dangling commas or spaces
                    cur.execute('''
                        UPDATE engineers
                        SET projects = TRIM(REPLACE(
                            REPLACE(REPLACE(projects, ?, ''), ', ,', ','), 
                            ', ', ','
                        ))
                        WHERE employee_name = ?
                    ''', (project_details[0], engineer))

                # Determine engineers to add
                engineers_to_add = new_engineers - existing_engineers
                # print("engineers_to_add:", engineers_to_add)

                # Add new engineers by appending the project name
                for engineer in engineers_to_add:
                    # print("engineer:", engineer)
                    cur.execute('''
                        UPDATE engineers
                        SET projects = COALESCE(projects, '') || ?
                        WHERE employee_name = ?
                    ''', (f"{project_details[0]}, ", engineer))

                # Commit the transaction only if there were changes
                if engineers_to_add or engineers_to_remove:
                    con.commit()
                    # print("Project and engineer associations updated successfully.")
                    return {"message": "Project updated and engineer associations modified."}, 200
                else:
                    # print("No changes in engineer associations.")
                    return {"message": "No changes made to engineer associations."}, 200

        except sqlite3.Error as e:
            print(f"An error occurred while updating the project: {e}")
            raise



    def get_project_by_id(self, project_id, current_user):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch the project details only for the current_user
                cur.execute('''
                    SELECT p.id, p.project_name, p.authorizer, p.reporting_manager, p.created_date, 
                        p.project_type, p.progress, p.dut, 
                        GROUP_CONCAT(e.employee_name) as engineer_names
                    FROM projects p
                    LEFT JOIN engineers e ON e.projects LIKE ?
                    WHERE p.id = ? AND p.current_user = ?
                    GROUP BY p.id
                ''', (f'%{project_id}%', project_id, current_user))

                project = cur.fetchone()

                if project:
                    return {
                        "id": project[0],
                        "project_name": project[1],
                        "authorizer": project[2],
                        "reporting_manager": project[3],
                        "created_date": project[4],
                        "project_type": project[5],
                        "progress": project[6],
                        "dut": project[7],
                        "engineer_names": project[8]  # Combined engineer names
                    }

                return None
        except sqlite3.Error as e:
            print(f"An error occurred while fetching the project: {e}")
            return None

    def delete_project(self, db_path, project_name):
        try:
            with sqlite3.connect(db_path) as con:
                cur = con.cursor()

                # Find the project ID by project name
                cur.execute('''
                    SELECT id FROM projects WHERE project_name = ?
                ''', (project_name,))
                project = cur.fetchone()

                if project is None:
                    raise ValueError("Project not found")

                project_id = project[0]

                # Step 1: Remove the project name from engineers' projects column
                 # Step 1: Remove the project name from all engineers' projects column
                cur.execute('''
                    UPDATE engineers
                    SET projects = TRIM(REPLACE(
                        REPLACE(REPLACE(projects, ?, ''), ', ,', ','), 
                        ', ', ','
                    ))
                    WHERE projects LIKE ?
                ''', (f"{project_name},", f'%{project_name}%'))

                # Step 1: Delete associated SSH credentials
                cur.execute('''
                    DELETE FROM ssh_credentials WHERE project_id = ?
                ''', (project_id,))

                # Step 2: Delete the project
                cur.execute('''
                    DELETE FROM projects WHERE id = ?
                ''', (project_id,))

                # Find all associated engineer IDs
                cur.execute('''
                    SELECT engineer_id FROM project_test_engineers WHERE project_id = ?
                ''', (project_id,))
                engineer_ids = cur.fetchall()

                # Step 3: Delete associated entries in the junction table
                cur.execute('''
                    DELETE FROM project_test_engineers WHERE project_id = ?
                ''', (project_id,))

                # Step 4: Optionally delete test engineers if they are no longer associated with any projects
                for engineer_id in engineer_ids:
                    cur.execute('''
                        SELECT COUNT(*) FROM project_test_engineers WHERE engineer_id = ?
                    ''', (engineer_id[0],))
                    count = cur.fetchone()[0]
                    if count == 0:
                        cur.execute('''
                            DELETE FROM test_engineers WHERE id = ?
                        ''', (engineer_id[0],))

                con.commit()
                # print('Project and associated data deleted successfully.')
                return {"message": "Project deleted successfully"}, 200

        except ValueError as e:
            print(e)
            return {"error": str(e)}, 404
        except sqlite3.IntegrityError as e:
            print(f"Integrity error occurred: {e}")
            return {"error": "Integrity error"}, 400
        except sqlite3.Error as e:
            print(f"An error occurred while deleting the project: {e}")
            return {"error": "Database error"}, 500

    def list_engineers(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Query to fetch engineers along with their assigned projects from the engineers table
                cur.execute('''
                    SELECT e.id, e.employee_name, e.email, e.phone_number, e.eng_id, e.position, e.company_name, 
                        e.projects
                    FROM engineers e
                    WHERE e.current_user = ?
                ''', (current_user_str,))

                engineers = cur.fetchall()

                # Convert to dictionary for easier handling in web apps
                engineer_list = []
                for engineer in engineers:
                    # print("engineer:",engineer)
                    engineer_list.append({
                        "id": engineer[0],
                        "employee_name": engineer[1],
                        "email": engineer[2],
                        "phone_number": engineer[3],
                        "eng_id": engineer[4],
                        "position": engineer[5],
                        "company_name": engineer[6],
                        "projects": engineer[7] if engineer[7] else "No projects assigned"
                    })

                return engineer_list

        except sqlite3.Error as e:
            print(f"An error occurred while listing engineers: {e}")
            return []

    def add_engineer(self, db_path, engineer_details, current_user):
        try:
            employee_name, email, phone_number, eng_id, position, company_name = engineer_details
            
            with sqlite3.connect(db_path) as con:
                cur = con.cursor()
                
                # Insert engineer into the engineers table
                cur.execute('''
                    INSERT INTO engineers (employee_name, email, phone_number, eng_id, position, company_name, current_user)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (employee_name, email, phone_number, eng_id, position, company_name, current_user.username))
                # print("current_user.username:", current_user.username)
                con.commit()
                return {"status": "success", "message": "Engineer added successfully."}
        except sqlite3.IntegrityError as e:
            return {"status": "error", "message": f"Integrity error: {e}"}
        except Exception as e:
            return {"status": "error", "message": f"An unexpected error occurred: {e}"}

    def get_engineer_by_id(self, engineer_id):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('SELECT * FROM engineers WHERE id = ?', (engineer_id,))
                engineer = cur.fetchone()
                return {
                    "id": engineer[0],
                    "employee_name": engineer[1],
                    "email": engineer[2],
                    "phone_number": engineer[3],
                    "eng_id": engineer[4],
                    "position": engineer[5],
                    "company_name": engineer[6]
                } if engineer else None
        except sqlite3.Error as e:
            print(f"An error occurred while fetching the engineer: {e}")
            return None
        
    def update_engineer(self, engineer_details):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('''
                    UPDATE engineers SET email = ?, phone_number = ?, 
                    eng_id = ?, position = ?, company_name = ? WHERE id = ?
                ''', engineer_details)
                con.commit()
                return {"status": "success", "message": "Engineer updated successfully."}
        except Exception as e:
            return {"status": "error", "message": f"An error occurred: {e}"}
    
    

    def list_project_type(self):
            try:
                with sqlite3.connect(self.db_path) as con:
                    cur = con.cursor()
                    cur.execute('SELECT type_name FROM Project_Type')
                    project_type = [row[0] for row in cur.fetchall()]
                return project_type
            except Exception as e:
                print(f"Error retrieving project type: {e}")
            return []
    
    def list_subtypes_by_project_type(self, project_type, limit=None):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                # print(f"Querying subtypes for project type: {project_type} with limit {limit}")

                # Base query to select subtypes and their statuses based on the project type
                query = '''
                    SELECT subtypes.subtype_name
                    FROM subtypes
                    JOIN Project_Type ON subtypes.Project_Type_id = Project_Type.id
                    WHERE Project_Type.type_name = ?
                '''
                params = [project_type]

                # If limit is provided, modify the query to add a limit clause
                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cur.execute(query, params)
                
                subtypes = cur.fetchall()
                # print(subtypes)

                # Return a list of dictionaries with subtype names and statuses
                return [{'subtype_name': subtype[0]} for subtype in subtypes]
        except Exception as e:
            print(f"Error retrieving subtypes for project type '{project_type}': {e}")
            return []
        
    def get_status_by_subtype(self, subtype_name, project_name):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                
                # Query to get the status from the scan table
                query = '''
                    SELECT status 
                    FROM scan
                    JOIN projects ON scan.project_id = projects.id
                    WHERE scan.subtype_name = ? AND projects.project_name = ?
                '''
                
                cur.execute(query, (subtype_name, project_name))
                result = cur.fetchone()
                if result:
                    return result[0]  # Return the status
                else:
                    return "To-Do"  # Default status if not found
        except sqlite3.Error as e:
            print(f"Error fetching status: {e}")
            return "To-Do"  # Default in case of an error


    def calculate_project_progress(self, statuses):
        # print("statuses:", statuses)
        
        if not statuses:
            return 'Created', 0

        # Count the occurrences of each status
        status_counts = {}
        for status in statuses:
            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts[status] = 1

        total_tasks = len(statuses)
        done_tasks = status_counts.get('Done', 0)
        todo_tasks = status_counts.get('To-Do', 0)

        # Determine progress based on the statuses
        if total_tasks == 0:
            progress = 'Created'
        elif todo_tasks == 0:
            progress = 'Done'
        elif done_tasks == 0:
            progress = 'To-Do'
        else:
            progress_percentage = int((done_tasks / total_tasks) * 100)
            progress = 'In Progress'

        return progress


    def update_project_progress(self, project_id, progress):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('''
                    UPDATE projects
                    SET progress = ?
                    WHERE id = ?
                ''', (progress, project_id))
                con.commit()
                # print(f"Project progress updated successfully for project ID: {project_id}. New progress: {progress}")
        except sqlite3.Error as e:
            print(f"An error occurred while updating project progress: {e}")
    
    def get_progress_count(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Modify the query to filter by the current user
                cur.execute('''
                    SELECT 
                        CASE
                            WHEN progress LIKE 'In Progress%' THEN 'In Progress'
                            WHEN progress = 'Done' THEN 'Done'
                            WHEN progress = 'Created' THEN 'Created'
                            WHEN progress = 'To-Do' THEN 'To-Do'
                            ELSE 'Other'
                        END AS progress_status,
                        COUNT(*) AS count
                    FROM projects
                    WHERE current_user = ?  -- Filter by current user
                    GROUP BY progress_status
                ''', (current_user_str,))
                results = cur.fetchall()
                
                # Initialize counts with default values
                progress_counts = {
                    'Created': 0,
                    'In Progress': 0,
                    'To-Do': 0,
                    'Done': 0
                }
                
                # Populate counts based on query results
                for status, count in results:
                    if status in progress_counts:
                        progress_counts[status] = count

                return progress_counts

        except sqlite3.Error as e:
            print(f"An error occurred while fetching project progress counts: {e}")
            return {}

    def get_engineers_count(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('''
                    SELECT COUNT(*) AS engineers_count
                    FROM engineers
                    WHERE current_user = ?
                ''', (current_user_str,))
                result = cur.fetchone()
                engineers_count = result[0] if result else 0
            return engineers_count
        except sqlite3.Error as e:
            print(f"An error occurred while fetching engineers count: {e}")
            return 0

    def get_project_count(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                cur.execute('''
                    SELECT COUNT(*) AS project_count
                    FROM projects
                    WHERE current_user = ? 
                ''', (current_user_str,))
                result = cur.fetchone()
                project_count = result[0] if result else 0
            return project_count
        except sqlite3.Error as e:
            print(f"An error occurred while fetching project count: {e}")
            return 0

    def get_authorizer_by_project_name(self, project_name):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch the authorizer, reporting_manager, created_date from the projects table
                cur.execute('''
                    SELECT p.authorizer, p.reporting_manager, p.created_date
                    FROM projects p
                    WHERE p.project_name = ?
                ''', (project_name,))

                result = cur.fetchone()
                if result:
                    return {
                        "authorizer": result[0],
                        "reporting_manager": result[1],
                        "created_date": result[2]
                    }
                else:
                    return None
        except sqlite3.Error as e:
            print(f"An error occurred while fetching the authorizer and reporting manager: {e}")
            return None

    def get_engineers_by_project_name(self, project_name):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch engineers' names whose projects include the specified project name
                cur.execute('''
                    SELECT e.employee_name
                    FROM engineers e
                    WHERE e.projects LIKE ?
                ''', (f'%{project_name}%',))

                engineer_names = [row[0] for row in cur.fetchall()]
                return engineer_names
        except sqlite3.Error as e:
            print(f"An error occurred while fetching engineers for project: {e}")
            return []



    def get_engineers_by_agent_name(self, agent_name):
        """Get a list of engineers associated with a specific agent."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                
                # SQL query to fetch engineers for the given agent name
                cur.execute('''
                    SELECT 
                        e.engineer_name
                    FROM 
                        agents a
                    LEFT JOIN 
                        agent_engineers ae ON a.id = ae.agent_id
                    LEFT JOIN 
                        agent_engineer_id e ON ae.engineer_id = e.id
                    WHERE 
                        a.agent_name = ?
                ''', (agent_name,))
                
                engineers = cur.fetchall()
                
                # Extract the engineer names from the result
                engineer_names = [row[0] for row in engineers]
                # print("2030 engineer name: ", engineer_names)
                return engineer_names
            
        except Exception as e:
            print(f"Error fetching engineers by agent name: {e}")
            return []

    
    def get_projects_by_engineer_names(self, engineer_name):
        """Get all project details associated with a specific engineer name."""
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Ensure engineer_name is a string
                if isinstance(engineer_name, list) and len(engineer_name) == 1:
                    engineer_name = engineer_name[0]  # Extract the first item if it's a list

                # Retrieve project names associated with the given engineer name from the engineers table
                cur.execute('''
                    SELECT 
                        projects
                    FROM 
                        engineers
                    WHERE 
                        employee_name = ?
                ''', (engineer_name,))  # Pass the engineer name as a single string
                
                row = cur.fetchone()
                if row and row[0]:  # Ensure the projects field is not empty
                    # Split project names, removing any leading/trailing whitespace
                    project_names = [name.strip() for name in row[0].split(',') if name.strip()]
                    
                    # Retrieve project details for all project names
                    if project_names:
                        placeholders = ', '.join('?' for _ in project_names)
                        cur.execute(f'''
                            SELECT 
                                p.project_name, 
                                p.authorizer, 
                                p.reporting_manager, 
                                p.created_date, 
                                p.project_type, 
                                p.progress, 
                                p.dut,
                                pt.type_name AS project_type_name,
                                GROUP_CONCAT(s.subtype_name, ", ") AS subtypes
                            FROM 
                                projects p
                            JOIN 
                                Project_Type pt ON p.project_type = pt.type_name
                            LEFT JOIN
                                subtypes s ON pt.id = s.Project_Type_id
                            WHERE 
                                p.project_name IN ({placeholders})
                            GROUP BY
                                p.id
                        ''', project_names)
                        
                        projects = cur.fetchall()
                        
                        # Format the results
                        project_details = [{
                            "project_name": row[0],
                            "authorizer": row[1],
                            "reporting_manager": row[2],
                            "created_date": row[3],
                            "project_type": row[4],
                            "progress": row[5],
                            "dut": row[6],
                            "project_type_name": row[7],
                            "subtypes": row[8]  # Subtypes as a comma-separated string
                        } for row in projects]
                        
                        return project_details

                return []  # No projects found for the engineer

        except Exception as e:
            print(f"Error fetching projects by engineer name: {e}")
            return []


    def get_subtype_details_from_db(self, subtype_name, project_name):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Query to fetch related details from scan, scan_data, and projects tables
                query = '''
                    SELECT 
                        scan_data.agent_name,
                        scan_data.upload_date,
                        scan_data.upload_time,
                        projects.project_name,
                        scan.subtype_name,
                        scan.repo_dir,
                        scan.current_user,
                        scan_data.scan_id
                    FROM scan_data
                    JOIN scan ON scan_data.scan_id = scan.id
                    JOIN projects ON scan.project_id = projects.id
                    WHERE scan.subtype_name = ? AND projects.project_name = ?
                    ORDER BY scan_data.upload_date ASC, scan_data.upload_time ASC
                '''

                # Execute the query with subtype_name and project_name as parameters
                cur.execute(query, (subtype_name, project_name))

                # Fetch all matching rows
                subtype_details = cur.fetchall()

              
                # Commit changes
                con.commit()

                # Add engineer names for each agent in the result
                enhanced_subtype_details = []
                for detail in subtype_details:
                    agent_name = detail[0]  # agent_name is the 1st field in the result
                    engineer_names = self.get_engineers_by_agent_name(agent_name)
                    enhanced_subtype_details.append((*detail, engineer_names))

                return enhanced_subtype_details

        except sqlite3.Error as e:
            print(f"An error occurred while fetching subtype details: {e}")
            return []


    def get_file_uploads(self, current_user):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch file uploads with related data from scan, scan_data, and projects tables
                cur.execute('''
                    SELECT 
                        scan_data.agent_name,
                        scan_data.upload_date,
                        scan_data.upload_time,
                        projects.project_name,
                        scan.subtype_name,
                        scan.repo_dir,
                        scan.current_user,
                        scan_data.scan_id
                            
                    FROM scan_data
                    JOIN scan ON scan_data.scan_id = scan.id
                    JOIN projects ON scan.project_id = projects.id
                    WHERE scan.current_user = ?
                    ORDER BY scan_data.upload_date ASC, scan_data.upload_time ASC
                ''', (current_user_str,))

                uploads = cur.fetchall()

            
                con.commit()

                # Add engineer names to each file upload (assuming a method exists to fetch engineers)
                enhanced_uploads = []
                for upload in uploads:
                    agent_name = upload[0]  # agent_name is the 1st field in the result
                    engineer_names = self.get_engineers_by_agent_name(agent_name)
                    enhanced_uploads.append((*upload, engineer_names))

                return enhanced_uploads

        except sqlite3.Error as e:
            print(f"An error occurred while fetching file uploads: {e}")
            return []

    def delete_report(self, scan_id):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Delete the record from the scan table (which will automatically delete associated scan_data due to ON DELETE CASCADE)
                cur.execute('DELETE FROM scan WHERE id = ?', (scan_id,))

                con.commit()

            return {"status": "success", "message": "Report and associated data successfully deleted"}

        except sqlite3.Error as e:
            print(f"An error occurred while deleting the report: {e}")
            return {"status": "error", "message": str(e)}


    def get_report_by_scanid(self, scan_id):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch the repo_dir based on scan_id from the scan table
                cur.execute('''
                    SELECT 
                        scan.repo_dir
                    FROM scan
                    WHERE scan.id = ?
                ''', (scan_id,))

                data = cur.fetchall()

                return data if data else None

        except sqlite3.Error as e:
            print(f"An error occurred while fetching report data: {e}")
            return None

    def insert_EUTConfiguration(self,current_user,model_no, product_name, manufacturer, serial_no, software_version, hardware_version,product_no, Front_img_data,Side_img_data,Port_img_data):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                ID = uuid.uuid4().hex
            
                cur.execute('''
                    INSERT INTO EUTConfiguration (
                        id,customer ,model_no, product_name, manufacturer, serial_no, 
                        software_version, hardware_version,product_no ,front_img, side_img, port_img) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)''', 
                    (ID, str(current_user),model_no, product_name, manufacturer, serial_no, 
                    software_version, hardware_version,product_no, Front_img_data,Side_img_data,Port_img_data))
                con.commit()
                # print("Records EUTConfiguration created successfully")
        except sqlite3.Error as e:
            print(f"An error occurred while fetching report data: {e}")
            return None
        

    def list_dut_configurations(self, current_user):
        """List all DUT configurations for the current user."""
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # SQL query to fetch all configurations for the current user
                cur.execute('''
                    SELECT 
                        id, product_no, model_no, product_name, manufacturer, 
                        serial_no, software_version, hardware_version, 
                        front_img, side_img, port_img
                    FROM 
                        EUTConfiguration
                    WHERE 
                        customer = ?
                ''', (current_user_str,))

                configurations = cur.fetchall()

                # Return the data in a list of dictionaries
                return [
                    {
                        'id': row[0],
                        'product_no': row[1],
                        'model_no': row[2],
                        'product_name': row[3],
                        'manufacturer': row[4],
                        'serial_no': row[5],
                        'software_version': row[6],
                        'hardware_version': row[7],
                        'front_img': row[8],
                        'side_img': row[9],
                        'port_img': row[10]
                    }
                    for row in configurations
                ]
        except Exception as e:
            print(f"Error retrieving DUT configurations: {e}")
            return []
        
    def Delete_DUT(self, current_user, ID):
        try:
            current_user_str = str(current_user)
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Step 1: Get the product number for the DUT we want to delete
                cur.execute("SELECT product_no FROM EUTConfiguration WHERE ID = ?", (ID,))
                product_row = cur.fetchone()

                if not product_row:
                    return {"status": "error", "message": "DUT not found."}

                product_no = product_row[0]

                # Step 2: Check if there are related records in the 'projects' table
                cur.execute("SELECT COUNT(*) FROM projects WHERE dut = ?", (product_no,))
                project_count = cur.fetchone()[0]
                print("project_count:", project_count)

                if project_count > 0:
                    # If there are related records, do not delete and return a failure message
                    return {"status": "error", "message": "Please delete or update associated records in the Project table before deleting this DUT."}

                # Step 3: Proceed with deleting the DUT from EUTConfiguration if no related records are found
                cur.execute("DELETE FROM EUTConfiguration WHERE ID = ?", (ID,))
                con.commit()  # Commit the transaction

            return {"status": "success", "message": "Successfully deleted DUT"}  # Indicate success
        except Exception as e:
            print(f"Error deleting DUT: {e}")
            return {"status": "error", "message": str(e)}  # Indicate failure

        
    def update_EUTConfiguration(self, dut_id, current_user, model_no, product_name, manufacturer,
                                serial_no, software_version, hardware_version):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Print the values being updated for debugging
                # print(f"Updating EUTConfiguration for dut_id: {dut_id}")
                # print(f"Current user: {current_user}")
                # print(f"Model No: {model_no}")
                # print(f"Product Name: {product_name}")
                # print(f"Manufacturer: {manufacturer}")
                # print(f"Serial No: {serial_no}")
                # print(f"Software Version: {software_version}")
                # print(f"Hardware Version: {hardware_version}")


                # SQL update query to modify the existing configuration
                cur.execute('''
                    UPDATE EUTConfiguration 
                    SET 
                        model_no = ?, 
                        product_name = ?, 
                        manufacturer = ?, 
                        serial_no = ?, 
                        software_version = ?, 
                        hardware_version = ?
                    WHERE 
                        id = ? AND customer = ?
                ''', (model_no, product_name, manufacturer, serial_no, software_version,
                    hardware_version,  dut_id, str(current_user)))

                con.commit()  # Commit the changes
                # print("EUTConfiguration updated successfully")
        except sqlite3.Error as e:
            print(f"An error occurred while updating EUTConfiguration: {e}")
            return None


    def list_product_numbers(self, current_user):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()
                # Fetch product numbers associated with the current user
                cur.execute('SELECT product_no FROM EUTConfiguration WHERE customer= ?', (current_user.username,))
                product_numbers = [row[0] for row in cur.fetchall()]
            return product_numbers
        except Exception as e:
            print(f"Error retrieving product numbers: {e}")
        return []
    
    def is_engineer_associated(self, engineer_id):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Fetch the engineer name based on the engineer_id from the engineers table
                cur.execute('''
                    SELECT employee_name
                    FROM engineers
                    WHERE id = ?
                ''', (engineer_id,))
                engineer_name_result = cur.fetchone()

                # If the engineer name was found, proceed to check associations
                if engineer_name_result:
                    engineer_name = engineer_name_result[0]

                    # Check for associations in the agent_engineer_id table using engineer_name
                    cur.execute('''
                        SELECT COUNT(*)
                        FROM agent_engineer_id
                        WHERE engineer_name = ?
                    ''', (engineer_name,))
                    agent_count = cur.fetchone()[0]

                    # Check for associated projects in the engineers table
                    cur.execute('''
                        SELECT projects
                        FROM engineers
                        WHERE id = ?
                    ''', (engineer_id,))
                    projects = cur.fetchone()[0]

                    # Check if projects is not null or empty
                    project_count = 1 if projects else 0  # If projects is not empty, count it as an association

                    # Print the counts for debugging
                    # print(f"Engineer ID: {engineer_id}, Engineer Name: {engineer_name}, Agent Count: {agent_count}, Project Count: {project_count}")

                    return agent_count > 0 or project_count > 0
                else:
                    # print(f"No engineer found with ID: {engineer_id}")
                    return False  # No engineer found with the given ID
        except sqlite3.Error as e:
            print(f"Error checking engineer associations: {e}")
            return False



    def delete_engineer(self, engineer_id):
        try:
            with sqlite3.connect(self.db_path) as con:
                cur = con.cursor()

                # Delete the engineer from the engineers table
                cur.execute('DELETE FROM engineers WHERE id = ?', (engineer_id,))
                if cur.rowcount == 0:
                    return {"status": "error", "message": "Engineer not found."}

                con.commit()
                return {"status": "success", "message": "Engineer deleted successfully."}
        except sqlite3.Error as e:
            print(f"Error deleting engineer: {e}")
            return {"status": "error", "message": "Failed to delete engineer."}
