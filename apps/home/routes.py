
import os
from apps.home import blueprint
from flask import render_template, request , flash, url_for, request, redirect,send_from_directory,abort
from flask_login import login_required
from apps.home.models import Model
from flask import send_file
from flask_login import (
    current_user,
    login_user,
    logout_user
)
import logging
from flask import jsonify
from apps.authentication.forms import LoginForm, CreateAccountForm
import sqlite3
import uuid
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()
DB_FOLDER = "./apps/DB/"



@blueprint.route('/index')
@login_required
def index():
    Model_obj = Model()
    # dash_data = Model_obj.Dash_getScan_details(current_user)
    agent_data = Model_obj.get_agents_count(current_user)
    agent_count = agent_data['agent_count']
    projects = Model_obj.list_projects_index(current_user)
   
    progress_count = Model_obj.get_progress_count(current_user)
    engineers_count = Model_obj.get_engineers_count(current_user)
    project_count = Model_obj.get_project_count(current_user)  # Add this line
    
    return render_template('home/index.html', 
                           segment='index', 
                        #    data=dash_data, 
                           agent_count=agent_count, 
                           progress_count=progress_count,
                           engineers_count=engineers_count,
                           project_count=project_count,projects=projects)  # Pass project_count to the template


@blueprint.route('/Dut_Configuration', methods=['GET', 'POST'])
@login_required
def Dut_Configuration():
    Model_obj = Model()
    
    # Fetch all EUT configurations at the start
    eut_configurations = Model_obj.list_dut_configurations(current_user)
    # print("eut_configurations:",eut_configurations)

    if request.method == 'POST':
        type_req = request.form['type']
        if type_req == "eut_conf":
            try:      
                model_no = request.form['ModelNo']
                product_name = request.form['ProductName']
                manufacturer = request.form['Mfg']
                serial_no = request.form['SN']
                software_version = request.form['SW_Version']
                hardware_version = request.form['HW_Version']
                product_no = request.form['product_no']

                Front_img_file = request.files['front_img']
                Front_img_data = Front_img_file.read() if Front_img_file else None

                Side_img_file = request.files['Side_img']
                Side_img_data = Side_img_file.read() if Side_img_file else None

                Port_img_file = request.files['Port_img']
                Port_img_data = Port_img_file.read() if Port_img_file else None

                Model_obj.insert_EUTConfiguration(
                    str(current_user), model_no, product_name, manufacturer, 
                    serial_no, software_version, hardware_version, product_no, 
                    Front_img_data, Side_img_data, Port_img_data
                )

                flash("You have successfully created DUT Configuration", "success")
                # Re-fetch EUT configurations to show the updated list
                eut_configurations = Model_obj.list_dut_configurations(current_user)
                return render_template('home/dut_configuration.html', segment='duts', eut_configurations=eut_configurations)

            except Exception as e:
                flash("Failed to create DUT main Configuration: " + str(e), "error")
                return render_template('home/dut_configuration.html', segment='duts', eut_configurations=eut_configurations)

    try:
        if 'delete' in request.args:
            delete = request.args['delete']
            delete_result = Model_obj.Delete_DUT(current_user, delete)

            if delete_result['status'] == "success":
                flash(delete_result['message'], "success")
            else:
                flash(delete_result['message'], "error")

            eut_configurations = Model_obj.list_dut_configurations(current_user)
            return render_template('home/dut_configuration.html', segment='duts', eut_configurations=eut_configurations)

    except Exception as e:
        flash("Failed to delete DUT: " + str(e), "error")


    return render_template('home/dut_configuration.html', segment='duts', eut_configurations=eut_configurations)



@blueprint.route('/Dut_Configuration/edit/<dut_id>', methods=['POST'])
def edit_dut_configuration(dut_id):
    try:
        Model_obj = Model()
     
        # print("dut_id:",dut_id)
        model_no = request.form.get('ModelNo')
        product_name = request.form.get('ProductName')
        manufacturer = request.form.get('Manufacturer')
        serial_no = request.form.get('SerialNo')
        software_version = request.form.get('SoftwareVersion')
        hardware_version = request.form.get('HardwareVersion')
        # product_no = request.form.get('product_no')

        # Front_img_file = request.files.get('front_img')
        # Side_img_file = request.files.get('Side_img')
        # Port_img_file = request.files.get('Port_img')

        # Front_img_data = Front_img_file.read() if Front_img_file else None
        # Side_img_data = Side_img_file.read() if Side_img_file else None
        # Port_img_data = Port_img_file.read() if Port_img_file else None

        Model_obj.update_EUTConfiguration(
            dut_id, str(current_user), model_no, product_name, manufacturer,
            serial_no, software_version, hardware_version
        )

        flash("You have successfully updated the EUT Configuration", "success")
        return redirect(url_for('home_blueprint.Dut_Configuration')) 
    except Exception as e:
        logging.error(f"Error updating EUT Configuration: {e}")
        return "Bad Request", 400

@blueprint.route('/reports', methods=['GET'])
@login_required
def file_uploads():
    Model_obj = Model()
    uploads_data = Model_obj.get_file_uploads(current_user)
   
    # print(f"File Uploads Data: {uploads_data}")
    
    return render_template('home/scans.html', uploads=uploads_data)

@blueprint.route('/delete_report', methods=['POST'])
@login_required
def delete_report():
    scan_id = request.form.get('scan_id')
    if scan_id:
        Model_obj = Model()
        delete_result = Model_obj.delete_report(scan_id)

        if delete_result['status'] == 'success':
            return jsonify({"status": "success", "message": delete_result['message']})
        else:
            return jsonify({"status": "error", "message": delete_result['message']}), 400
    else:
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400


@blueprint.route('/view_report_files', methods=['GET'])
def view_report_files():
    scan_id = request.args.get('id')  # Fetch scan_id from request
    # print("scan_id:", scan_id)
    Model_obj = Model()

    # Fetch the report directory path for the given scan_id
    scan_data = Model_obj.get_report_by_scanid(scan_id)

    if not scan_data:
        return render_template('home/scan_report.html', files=[], message="Scan not found.")

    report_directory = scan_data[0][0]  # Assuming repo_dir is the 1st field in the record

    report_directory = scan_data[0][0]
    
    # Define image extensions to check against
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}  
    try:
        all_files = os.listdir(report_directory)

        # Separate files
        files = [file for file in all_files if not any(file.lower().endswith(ext) for ext in image_extensions)]
        images = [file for file in all_files if any(file.lower().endswith(ext) for ext in image_extensions)]
        
        # Get basenames without extensions
        image_basenames = [os.path.splitext(image)[0] for image in images]

        show_table = not bool(images)  # Only show table if there are no images
    except FileNotFoundError:
        files = []
        images = []
        image_basenames = []  # Ensure this is empty on error
        show_table = True

    # Render template with separated file lists and show_table flag
    return render_template(
        'home/scan_report.html',
        files=files,
        images=images,
        image_basenames=image_basenames,  # Pass the basenames to the template
        show_table=show_table,
        report_directory=report_directory,
        id=scan_id
    )
# @blueprint.route('/view_subtype_report_files', methods=['GET'])
# def view_subtype_report_files():
#     scan_id = request.args.get('id')  # Fetch scan_id from request
#     print("scan_id:", scan_id)
#     Model_obj = Model()

#     # Fetch the report directory path for the given scan_id
#     scan_data = Model_obj.get_report_by_scanid(scan_id)

#     if not scan_data:
#         return render_template('home/subtype_report.html', files=[], message="Scan not found.")

#     report_directory = scan_data[0][0]  # Assuming repo_dir is the 1st field in the record
    
#     # List all files in the report directory, excluding .pcap files
#     try:
#         all_files = os.listdir(report_directory)
#         files = [file for file in all_files]  # Exclude .pcap files
#     except FileNotFoundError:
#         files = []

#     # Render the scan_report.html with the list of files, report directory, and agent_name
#     return render_template('home/scan_report.html', files=files, report_directory=report_directory, id=scan_id)

@blueprint.route('/view_subtype_report_files', methods=['POST'])
def view_subtype_report_files():
    project_type = request.form.get('project_type')
    project_name = request.form.get('project_name')
    project_dut = request.form.get('project_dut')
    subtype_name = request.form.get('subtype_name')
    scan_id = request.form.get('id')
    Model_obj = Model()

    # Fetch the report directory path for the given scan_id
    scan_data = Model_obj.get_report_by_scanid(scan_id)
    if not scan_data:
        return render_template('home/subtype_report.html', files=[], images=[], show_table=True, message="Scan not found.")

    report_directory = scan_data[0][0]

    # Define image extensions to check against
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}  
    try:
        all_files = os.listdir(report_directory)

        # Separate files
        files = [file for file in all_files if not any(file.lower().endswith(ext) for ext in image_extensions)]
        images = [file for file in all_files if any(file.lower().endswith(ext) for ext in image_extensions)]
        
        # Get basenames without extensions
        image_basenames = [os.path.splitext(image)[0] for image in images]

        show_table = not bool(images)  # Only show table if there are no images
    except FileNotFoundError:
        files = []
        images = []
        image_basenames = []  # Ensure this is empty on error
        show_table = True

    # Render template with separated file lists and show_table flag
    return render_template(
        'home/scan_report.html',
        files=files,
        images=images,
        image_basenames=image_basenames,  # Pass the basenames to the template
        show_table=show_table,
        report_directory=report_directory,
        id=scan_id,
        project_name =project_name , project_type=project_type,project_dut=project_dut,subtype_name=subtype_name
    )


@blueprint.route('/view_image/<path:report_directory>/<path:filename>', methods=['GET'])
def view_image(report_directory, filename):
    # Get the current working directory
    cwd = os.getcwd()
    
    # Construct the full path using the current working directory
    full_path = os.path.join(cwd, report_directory)

    # Optional: Debugging output to verify the full path
    print(f"Serving file from: {full_path} with filename: {filename}")
    
    # Send the requested file
    return send_from_directory(full_path, filename)

@blueprint.route('/download_file/<id>/<filename>', methods=['GET'])
def download_file(id, filename):
    Model_obj = Model()
    
    # Check the current working directory
    current_directory = os.getcwd()
    # print("Current Working Directory:", current_directory)
    
    # Get the report directory path for the given agent
    agent_data = Model_obj.get_report_by_scanid(id)
    if not agent_data:
        return "Agent not found", 404

    # Convert report_directory to an absolute path
    report_directory = os.path.abspath(agent_data[0][0])
    # print("Report Directory (Absolute Path):", report_directory)
    
    # List files in the report directory
    try:
        files_in_directory = os.listdir(report_directory)
        # print("Files in Report Directory:", files_in_directory)
    except FileNotFoundError:
        return "Report directory not found", 404
    except Exception as e:
        # current_app.logger.error(f"Error listing files in directory: {str(e)}")
        return str(e), 500
    
    # Construct the absolute file path
    file_path = os.path.join(report_directory, filename)
    # print("File Path:", file_path)
    
    # Check if the file exists in the report directory
    if not os.path.isfile(file_path):
        return abort(404, description="File not found")
    
    # Use send_from_directory to serve the file
    try:
        return send_from_directory(report_directory, filename, as_attachment=True)
    except Exception as e:
        # current_app.logger.error(f"Error sending file: {str(e)}")
        return str(e), 500


@blueprint.route('/agents', methods=['GET'])
@login_required
def agent_management():
    """Retrieve all agents for the current user."""
    model_obj = Model()
    agents = model_obj.list_agents(current_user)
   
    print(f"Agents retrieved: {agents}") 
    
    return jsonify({"agents": agents})

@blueprint.route('/create/agents', methods=['POST'])
@login_required
def create_agent():
    """Create a new agent."""
    data = request.get_json()
    agent_name = data.get('name')
    engineer_name = data.get('engineers')  # Expect a single engineer name
    print("Engineer name: ", engineer_name)

    if not agent_name:
        return jsonify({"error": "Agent name is required"}), 400

    if not engineer_name:
        return jsonify({"error": "Engineer name is required"}), 400

    model_obj = Model()
    result, status_code = model_obj.create_agent(agent_name, current_user, engineer_name)
    return jsonify(result), status_code

@blueprint.route('/agents/delete/<agent_name>', methods=['DELETE'])
@login_required
def delete_agent(agent_name):
    """Delete an agent by name."""
    model_obj = Model()
    result, status_code = model_obj.delete_agent(agent_name, current_user)
    return jsonify(result), status_code

@blueprint.route('/agent_management', methods=['GET'])
@login_required
def show_agent_management_page():
    
    model_obj = Model()
    engineers = model_obj.list_engineers(current_user) 
    return render_template('home/agent_management.html',segment='agent', engineers=engineers)


@blueprint.route('/download_agent_installer', methods=['GET'])
def download_agent_installer():
    # Get the path to the static folder
    static_folder = os.path.join(os.getcwd(), 'apps/static')
    print("static_folder:", static_folder)

    # File name
    filename = 'dlpl-agent.zip'
    print("filename:", filename)
    # Check if the file exists
    if not os.path.isfile(os.path.join(static_folder, filename)):
        return abort(404, description="Installer not found")
    
    # Serve the file from the static folder
    try:
        return send_from_directory(static_folder, filename, as_attachment=True)
    except Exception as e:
        return str(e), 500
    
@blueprint.route('/validate_key', methods=['POST'])
def validate_key():
    """Validate an API key."""
    data = request.json
    api_key = data.get('api_key')
    token = data.get('token')

    print(f"Received API Key: {api_key}")
    print(f"Received Token: {token}")

    model_obj = Model()

    if token:
        # If token is provided, validate it directly
        result, status_code = model_obj.validate_api_key(token=token)
    else:
        # If no token, validate the API key and generate a new token
        if not api_key:
            return jsonify({"error": "API key is required"}), 400
        result, status_code = model_obj.validate_api_key(api_key=api_key)
       
    return jsonify(result), status_code

@blueprint.route('/get_eut_configuration', methods=['POST'])
def get_eut_configuration():
    """Get EUT configuration, update API validation status, and fetch project details for engineers."""
    data = request.json
    token = data.get('token')
    print("token:",token)

    if not token:
        return jsonify({"error": "Token is required"}), 400

    model_obj = Model()

    # Validate the API key and possibly update the token
    result, status_code = model_obj.validate_api_key(token=token)

    if status_code != 200:
        token = model_obj.update_token_for_agent(result.get("agent_name")).get("new_token")
        result["token"] = token
        return jsonify(result), status_code

    customer = result.get("current_user")
    agent_name = result.get("agent_name")
    if not customer or not agent_name:
        return jsonify({"error": "Current user or agent name not found"}), 404

    # Fetch engineers associated with the agent
    engineer_names = model_obj.get_engineers_by_agent_name(agent_name)
    if not engineer_names:
        return jsonify({"data": [], "agent_name": agent_name}), 200

    # Fetch project details for the engineers
    project_details = model_obj.get_projects_by_engineer_names(engineer_names)
    # print("1530:", project_details)
    return jsonify({
        "data": project_details,
        "agent_name": agent_name,
        "token": token
    }), 200

def generate_unique_id():
    return uuid.uuid4().hex



# @blueprint.route('/project_scan_id', methods=['POST'])
# def project_scan_id():
#     """Handle the request to create a scan ID based on the client's UID and selection."""
#     data = request.json
#     project = data.get('project')
#     test_case = data.get('test_case')

#     if not project or not test_case:
#         return jsonify({"error": "Invalid input"}), 400

#     # Initialize the model
#     model_obj = Model()
    
#     # Use the token for directory creation
#     result = model_obj.get_scan_id(project, test_case)
    
#     if not result:
#         return jsonify({"error": "Failed to get scan id"}), 500
    
#     return jsonify({
#         "result_path": result['scan_id']
#     }), 200


@blueprint.route('/create_scan_id', methods=['POST'])
def create_scan_id():
    """Handle the request to create a scan ID based on the client's UID and selection."""
    data = request.json
    # print("data:", data)
    
    project = data.get('project')
    test_case = data.get('test_case')

    if not project or not test_case:
        return jsonify({"error": "Invalid input"}), 400

    # Generate a new session ID
    session_id = generate_unique_id()

    # Create the scan ID
    scan_id = f"{session_id}"

    # Initialize the model
    model_obj = Model()
    
    # Use the token for directory creation
    result = model_obj.create_scan_id(scan_id, project, test_case)
    
    if "error" in result:
        return jsonify({"error": result["error"]}), 400 

    # Extract scan_id and repo_dir from the result
    repo_dir = result.get('repo_dir')
    scan_id = result.get('scan_id')
    username = result.get('ssh_username')
    password = result.get('ssh_password')
    project_type = result.get('project_type')
    
    # Print the output
    # print(f"project_type: a{project_type}")
    # print(f"Repository Directory: {repo_dir}")
    # print(f"SSH Username: {username}")
    # print(f"SSH Password: {password}")


    # Ensure both scan_id and repo_dir are available
    if not repo_dir or not scan_id or not username or not password or not project_type:
        return jsonify({"error": "Missing repo_dir or scan_id or username or password in result"}), 500

    # Retrieve DUT details based on the product_no of the project
    dut_details = model_obj.get_dut_details(project)

    # print("dut_details:",dut_details)
    if "error" in dut_details:
        return jsonify({"error": dut_details["error"]}), 400

    # Return the response with scan_id, repo_dir, SSH credentials, project type, and DUT details
    return jsonify({
        "scan_id": scan_id,
        "repo_dir": repo_dir,
        'ssh_username': username,
        'ssh_password': password,
        'project_type': project_type,
        'dut_details': dut_details  # Return DUT details
    }), 200


@blueprint.route('/upload', methods=['POST'])
def upload_data():
    """Handle file uploads and store metadata in the database."""
    # Extract the data from the request form
    agent_name = request.json.get('agent_name')
    scan_id = request.json.get('scan_id')
    
    print("all data: ",agent_name, scan_id)
    # Check if any required fields are missing
    if not all([agent_name, scan_id]):
        return jsonify({'error': 'Missing required data'}), 400

    # Initialize the model
    model_obj = Model()

    # Store metadata in the database
    try:
        model_obj.store_metadata(agent_name,scan_id)
        return jsonify({'message': 'Data successfully stored in the database'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    


@blueprint.route('/upload_files', methods=['POST'])
def upload_files():
    # Get the repo_dir from the form data
    repo_dir = request.form.get('repo_dir')
    if not repo_dir:
        return jsonify({"message": "repo_dir is required"}), 400
    
    if 'files' not in request.files:
        return jsonify({"message": "No files part in request"}), 400
    
    files = request.files.getlist('files')
    
    for file in files:
        # Save the file to a specific directory
        file.save(f"{repo_dir}/{file.filename}")  # Save each file to the repo_dir
    
    return jsonify({"message": "Files successfully uploaded!", "repo_dir": repo_dir}), 200

@blueprint.route('/Project', methods=['GET'])
@login_required
def show_project_page():
    model_obj = Model()
    
    projects = model_obj.list_projects(current_user)
    engineers = model_obj.list_engineers(current_user) 
    product_numbers = model_obj.list_product_numbers(current_user)
    project_types = model_obj.list_project_type()
    
    # Update project progress based on subtype status data
    for project in projects:
        project_name = project['project_name']
        project_type = project['project_type']
        
        # Fetch subtypes related to the project
        subtypes = model_obj.list_subtypes_by_project_type(project_type)
        # print("subtype 1622:", subtypes)

        # Initialize status counts
        status_counts = {'To-Do': 0, 'In Progress': 0, 'Done': 0}
        
        for subtype in subtypes:  # Changed variable name to subtype
            # Get the status for each subtype
            subtype_status = model_obj.get_status_by_subtype(subtype['subtype_name'], project_name)
            subtype['status'] = subtype_status
            # print("subtype 1625:", subtype)

            # Increment the status count
            if subtype_status in status_counts:
                status_counts[subtype_status] += 1
        
        total_subtypes = sum(status_counts.values())
        
        # Calculate progress percentages
        if total_subtypes > 0:
            # print("total_subtypes:", total_subtypes)
            todo_percentage = (status_counts['To-Do'] / total_subtypes) * 100
            # print("todo_percentage:", todo_percentage)
            in_progress_percentage = (status_counts['In Progress'] / total_subtypes) * 100
            # print("in_progress_percentage:", in_progress_percentage)
            done_percentage = (status_counts['Done'] / total_subtypes) * 100
            # print("done_percentage:", done_percentage)
        else:
            todo_percentage = 0
            in_progress_percentage = 0
            done_percentage = 0
        
        # Update project progress based on done percentage or other criteria
        if done_percentage == 100:
            project['progress'] = 'Done'
        elif 0 < todo_percentage < 100:  # Changed condition to check for in-progress
            project['progress'] = 'In Progress'
        elif todo_percentage == 100:
            project['progress'] = 'To-Do'
        else:
            project['progress'] = 'Created'
        
        # Optionally, update the database with the calculated progress
        model_obj.update_project_progress(project['id'], project['progress'])
    
    return render_template('home/project.html', 
                           projects=projects, 
                           segment='project',
                           engineers=engineers, 
                           product_numbers=product_numbers,
                           project_type=project_types)

@blueprint.route('/view_subtypes', methods=['GET', 'POST'])
@login_required
def view_subtypes():
    project_name = request.form.get('project_name')
    project_type = request.form.get('project_type')
    project_dut = request.form.get('project_dut')
    
    # print("1563 project_dut: ", project_dut)
    if not project_type:
        return "Project Type not found", 400
    if not project_name:
        return "Project Name not found", 400
    if not project_dut:
        return "Project Dut not found", 400

    model_obj = Model()

    project_id = model_obj.get_project_id_by_name(project_name)
    if not project_id:
        return "Project ID not found", 404

    engineers = model_obj.list_engineers(current_user) 
    engineer_names_list_option = [engineer['employee_name'] for engineer in engineers]
 
    project_types_list = model_obj.list_project_type()
   
    
    
    subtypes = model_obj.list_subtypes_by_project_type(project_type, limit=5)
    # print("subtypes:",subtypes)
    for subtype in subtypes:
        subtype['status'] = model_obj.get_status_by_subtype(subtype['subtype_name'], project_name)
    
    product_numbers = model_obj.list_product_numbers(current_user)
    
    # Calculate counts for each status
    status_counts = {'To-Do': 0, 'In Progress': 0, 'Done': 0}
    total_tasks = 0
    # print(" subtypes:", subtypes)
    for subtype in subtypes:
        status = subtype['status']
        if status in status_counts:
            status_counts[status] += 1
            total_tasks += 1

    # Calculate percentages for To-Do and Done tasks
    todo_percentage = round((status_counts['To-Do'] / total_tasks) * 100) if total_tasks > 0 else 0
    done_percentage = round((status_counts['Done'] / total_tasks) * 100) if total_tasks > 0 else 0


    # Debugging: Print status counts and total tasks
    # print("1552 Status counts:", status_counts)
    # print("Total tasks:", total_tasks)
    
    # Get project info
    project_info = model_obj.get_authorizer_by_project_name(project_name)
    # print("1598: ", project_info)
    if project_info:
        authorizer = project_info.get('authorizer')
        reporting_manager = project_info.get('reporting_manager')
        created_date = project_info.get('created_date')
        
   
        
    else:
        authorizer = None
        reporting_manager = None
        engineer_names = None
        created_date = None
       
    engineer_names_list = model_obj.get_engineers_by_project_name(project_name)
    # print("engineer_names_list:",engineer_names_list)
        
    engineer_names = ', '.join(engineer_names_list)
    # print("engineer_names :",engineer_names )
        # Calculate total number of engineers if it's a comma-separated string
    total_engineers = len(engineer_names_list)
        
       

    return render_template('home/sub_type.html', 
                           subtypes=subtypes, 
                           authorizer=authorizer, 
                           reporting_manager=reporting_manager, 
                           project_type=project_type,
                           project_name=project_name, 
                           engineer_names=engineer_names, 
                           subtype_count=len(subtypes), 
                           created_date=created_date,
                           status_counts=status_counts,
                           total_tasks=total_tasks,
                           project_dut=project_dut,
                           todo_percentage=todo_percentage,
                           done_percentage=done_percentage,
                           engineers =engineers ,
                           engineer_names_list_option=engineer_names_list_option,
                           product_numbers=product_numbers,
                           project_types_list=project_types_list,
                           project_id=project_id,
                           total_engineers=total_engineers)

@blueprint.route('/view_all_subtype', methods=['POST'])
def view_all_subtype():
    project_type = request.form.get('project_type')
    project_name = request.form.get('project_name')
    project_dut = request.form.get('project_dut')
   
    print("project_type, project_name, project_dut:", project_type, project_name, project_dut)
    
    if not all([project_type, project_name, project_dut]):
        return "Required project details not found", 400

    model_obj = Model()
    subtypes = model_obj.list_subtypes_by_project_type(project_type)
    for subtype in subtypes:
        subtype['status'] = model_obj.get_status_by_subtype(subtype['subtype_name'], project_name)
    
    return render_template('home/all_subtype.html', subtypes=subtypes, project_name=project_name, project_type=project_type,project_dut=project_dut)


@blueprint.route('/subtype-details', methods=['POST'])
def subtype_details():
    subtype_name = request.form.get('subtype_name')
    # print("subtype_name:", subtype_name)
    project_type = request.form.get('project_type')
    project_name = request.form.get('project_name')
    project_dut = request.form.get('project_dut')
    # print("subtype_name:", subtype_name) # Get the project_name from the request
    model_obj = Model()

    # Fetch the details from the database based on the subtype_name and project_name
    subtype_details = model_obj.get_subtype_details_from_db(subtype_name, project_name)
    # print("subtype_details: ", subtype_details)
    # Render the template to display the subtype details
    return render_template('home/subtype_details.html', uploads=subtype_details,project_name=project_name, project_type=project_type,project_dut=project_dut,subtype_name=subtype_name)



@blueprint.route('/create_project', methods=['POST'])
@login_required
def create_project():
    if request.method == 'POST':
        try:
            # Extract form data
            project_name = request.form.get('name')
            authorizer = request.form.get('Auth')
            reporting_manager = request.form.get('RM')
            project_type = request.form.get('Pro_Type')
            # progress = request.form.get('Prog')
            dut = request.form.get('Dut')
            # Set created_date to the current date
            created_date = datetime.now().strftime('%Y-%m-%d')

            # Extract engineer names from the form
            engineer_names = request.form.getlist('engineers')  # Changed to getlist for multiple checkboxes

            # Check if all required fields are provided
            if not all([project_name, authorizer, reporting_manager, project_type, dut]):
                flash('All fields are required. Please fill out all fields.', 'error')
                return redirect(url_for('home_blueprint.show_project_page'))

            # Prepare project details for insertion
            project_details = (
                project_name, authorizer, reporting_manager, created_date, project_type, dut
            )
            
            # Call the function to add the project and associate engineers
            model_obj = Model()
            model_obj.add_project(db_path=model_obj.db_path, project_details=project_details, engineer_names=engineer_names, current_user=current_user)
            
            # Flash a success message and redirect to the project page
            # flash('Project added successfully!', 'success')
            return redirect(url_for('home_blueprint.show_project_page'))
        except sqlite3.IntegrityError as e:
            flash('Project with this name already exists. Please choose a different name.', 'error')
            return redirect(url_for('home_blueprint.show_project_page'))
        except Exception as e:
            flash(f'Error adding project: {e}', 'error')
            return redirect(url_for('home_blueprint.show_project_page'))



@blueprint.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    model_obj = Model()

    if request.method == 'POST':
        try:
            # Extract form data
            project_name = request.form.get('name')
            authorizer = request.form.get('Auth')
            reporting_manager = request.form.get('RM')
            project_type = request.form.get('Pro_Type')
            project_dut = request.form.get('Dut')
            
            # Extract engineer names from the form
            engineer_names = request.form.getlist('engineers')
            # print("all data", project_name, authorizer, reporting_manager, project_type, dut, engineer_names)
            
            # Check if all required fields are provided
            if not all([project_name, authorizer, reporting_manager, project_type, project_dut]):
                flash('All fields are required. Please fill out all fields.', 'error')
                return redirect(url_for('home_blueprint.view_subtypes', 
                        project_name=project_name, 
                        project_type=project_type, 
                        project_dut=project_dut))

            # Get current user
            current_user_str = str(current_user)

            # Prepare updated project details for insertion, including current_user
            project_details = (
                project_name, authorizer, reporting_manager, project_type, project_dut, current_user_str, project_id
            )
            # print("project update : ", project_details)

            # Update project and associated engineers
            model_obj.update_project(project_details=project_details, engineer_names=engineer_names)
            
            flash('Project updated successfully!', 'success')
            return redirect(url_for('home_blueprint.view_subtypes', 
                        project_name=project_name, 
                        project_type=project_type, 
                        project_dut=project_dut))
        
        except sqlite3.Error as e:
            flash(f'Error updating project: {e}', 'error')
            return redirect(url_for('home_blueprint.view_subtypes', 
                        project_name=project_name, 
                        project_type=project_type, 
                        project_dut=project_dut))

    else:
        # print("else")
        # Fetch existing project details
        project = model_obj.get_project_by_id(project_id, str(current_user))
        if not project:
            flash('Project not found.', 'error')
            return redirect(url_for('home_blueprint.view_subtypes', 
                        project_name=project_name, 
                        project_type=project_type, 
                        project_dut=project_dut))


@blueprint.route('/delete_project', methods=['POST'])
@login_required
def delete_project():
    if request.method == 'POST':
        try:
            # Extract project name from the form
            project_name = request.form.get('project_name')

            if not project_name:
                flash('Project name is required to delete a project.', 'error')
                return redirect(url_for('home_blueprint.show_project_page'))

            # Call the function to delete the project
            model_obj = Model()
            model_obj.delete_project(db_path=model_obj.db_path, project_name=project_name)
            
            # Flash a success message and redirect to the project page
            # flash('Project deleted successfully!', 'success')
            return redirect(url_for('home_blueprint.show_project_page'))
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(url_for('home_blueprint.show_project_page'))
        except sqlite3.Error as e:
            flash(f'Error deleting project: {e}', 'error')
            return redirect(url_for('home_blueprint.show_project_page'))

@blueprint.route('/engineers', methods=['GET'])
@login_required
def show_engineer_page():
    model_obj = Model()
    engineers = model_obj.list_engineers(current_user) 
    # print("1807 engineers: ", engineers)
   
    return render_template('home/engineer.html',segment='engineers', engineers=engineers)

@blueprint.route('/add_engineer', methods=['POST'])
@login_required
def create_engineer():
    if request.method == 'POST':
        try:
            # Extract form data
            employee_name = request.form.get('employee_name')
            email = request.form.get('email')
            phone_number = request.form.get('phone_number')
            eng_id = request.form.get('eng_id')
            position = request.form.get('position')
            company_name = request.form.get('company_name')
            
            # Check if all required fields are provided
            if not all([employee_name, email, phone_number, eng_id, position, company_name]):
                flash('All fields are required. Please fill out all fields.', 'error')
                return redirect(url_for('home_blueprint.show_engineer_page'))

            engineer_details = (
                employee_name, email, phone_number, eng_id, position, company_name
            )
            
            model_obj = Model()
            result = model_obj.add_engineer(db_path=model_obj.db_path, engineer_details=engineer_details, current_user=current_user)
            
            # Flash result message based on the status
            flash(result['message'], 'success' if result['status'] == 'success' else 'error')
            return redirect(url_for('home_blueprint.show_engineer_page'))
        except Exception as e:
            flash(f'Error adding engineer: {e}', 'error')
            return redirect(url_for('home_blueprint.show_engineer_page'))

@blueprint.route('/edit_engineer/<int:engineer_id>', methods=['GET', 'POST'])
@login_required
def edit_engineer(engineer_id):
    model_obj = Model()

    if request.method == 'POST':
        # Handle the form submission
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        eng_id = request.form.get('eng_id')
        position = request.form.get('position')
        company_name = request.form.get('company_name')

        engineer_details = (email, phone_number, eng_id, position, company_name, engineer_id)
        result = model_obj.update_engineer(engineer_details=engineer_details)
        flash(result['message'], 'success' if result['status'] == 'success' else 'error')
        return redirect(url_for('home_blueprint.show_engineer_page'))

    engineer = model_obj.get_engineer_by_id(engineer_id)
    # print("Engineer 1849:", engineer)
    return jsonify(engineer) 



@blueprint.route('/delete_engineer', methods=['POST'])
def delete_engineer():
    engineer_id = request.form.get('engineer_id')
    model_obj = Model()

    # Check if the engineer is associated with any agents or projects
    if model_obj.is_engineer_associated(engineer_id):
        return jsonify({"success": False, "message": "Please delete the associated entries first."})

    try:
        # Proceed to delete the engineer
        result = model_obj.delete_engineer(engineer_id)
        if result['status'] == 'success':
            return jsonify({"success": True, "redirect_url": url_for('home_blueprint.show_engineer_page')})
        else:
            return jsonify({"success": False, "message": result['message']})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})