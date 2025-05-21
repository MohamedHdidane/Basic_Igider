from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import os
import pathlib
import base64

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    wrapper = False
    note = "Simple Python agent for basic callback and task execution"
    
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["py", "base64"],
            default_value="py",
            description="Output format"
        )
    ]
    
    c2_profiles = ["http"]
    
    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        
        try:
            # Get base agent code
            agent_code_path = os.path.join(
                pathlib.Path(__file__).parent.resolve(),
                "agent_code",
                "base_code.py"
            )
            
            with open(agent_code_path, "r") as f:
                base_code = f.read()
            
            # Apply C2 profile configuration
            for c2 in self.c2info:
                params = c2.get_parameters_dict()
                base_code = base_code.replace("callback_host", params.get("host", ""))
                base_code = base_code.replace("callback_port", params.get("port", ""))
                base_code = base_code.replace("/post_uri", params.get("post_uri", ""))
                base_code = base_code.replace("/get_uri", params.get("get_uri", ""))
                base_code = base_code.replace("query", params.get("query_param", ""))
                base_code = base_code.replace("UUID_HERE", self.uuid)
                
                # Set sleep time if provided
                if "callback_interval" in params:
                    base_code = base_code.replace("Sleep\": 10", f"Sleep\": {params['callback_interval']}")
                
                # Set jitter if provided
                if "callback_jitter" in params:
                    base_code = base_code.replace("Jitter\": 0", f"Jitter\": {params['callback_jitter']}")
                
                # Set killdate if provided
                if "killdate" in params:
                    base_code = base_code.replace("KillDate\": \"\"", f"KillDate\": \"{params['killdate']}\"")
            
            # Format output
            if self.get_parameter("output") == "base64":
                resp.payload = base64.b64encode(base_code.encode())
            else:
                resp.payload = base_code.encode()
                
        except Exception as e:
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = str(e)
            
        return resp