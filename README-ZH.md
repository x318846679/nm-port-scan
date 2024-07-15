Network Port Scanning and Task Management System
Project Introduction
This project is a network port scanning and task management system based on the Flask framework. The main features of the system include:

Scanning open ports of specified IP addresses
Managing scanning tasks
Scheduled execution of scanning tasks
Sending scanning results via email
User management and permission control
Login logs and access records
Features
Task Management: Users can create, execute, terminate, and delete port scanning tasks.
Scheduled Tasks: Support setting task execution intervals for automatic scheduled scanning.
Email Notifications: Upon task completion, the system sends the scanning results to the specified email address.
User Management: Administrators can add, edit, and delete users and set user permissions.
Access Records: The system records user login information and access logs to prevent malicious attacks.
Installation Steps
Clone the Project

git clone https://github.com/your-username/port-scanner.git
cd port-scanner
Create a Virtual Environment and Install Dependencies

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
Configure the Database

flask db init
flask db migrate
flask db upgrade
Run the Application

flask run
Usage
Register and Login

Visit http://127.0.0.1:5000, and log in with the default admin account admin. You can create new users after logging in.

Create Tasks

After logging in, fill in the task information, including the task name, IP address, and scanning parameters on the task management page. Click submit to create the task.

View Tasks

On the task list page, you can view the status and progress of all tasks and execute, terminate, or delete tasks.

Scheduled Tasks

When creating a task, you can set the task execution interval (in minutes), and the system will execute the task at the set intervals.

Developer Information
Author: SpiderMan
GitHub: https://github.com/x318846679
