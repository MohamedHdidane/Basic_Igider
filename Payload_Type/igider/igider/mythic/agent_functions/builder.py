from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
import pathlib
import os
import base64

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    wrapper = False
    mythic_encrypts = True
    supports_dynamic_loading = True
    c2_profiles = ["http"]
    _BASE_DIR = pathlib.Path(".")

    @property
    def agent_code_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "agent_code"

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        try:
            # Load base agent code
            base_agent_path = os.path.join(self.agent_code_path, "base_agent.py")
            if not os.path.exists(base_agent_path):
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "Base agent code not found"
                return resp
            with open(base_agent_path, "r") as f:
                base_code = f.read()

            # Load command modules
            command_code = ""
            for cmd in self.commands.get_commands():
                cmd_path = os.path.join(self.agent_code_path, f"{cmd}.py")
                if os.path.exists(cmd_path):
                    with open(cmd_path, "r") as f:
                        command_code += f.read() + "\n"
                else:
                    resp.build_stderr = f"Command module '{cmd}' not found"

            # Apply configurations
            base_code = base_code.replace("#COMMANDS_PLACEHOLDER", command_code)
            base_code = base_code.replace("UUID_HERE", self.uuid)
            for c2 in self.c2info:
                for key, value in c2.get_parameters_dict().items():
                    base_code = base_code.replace(key, str(value) if value is not None else "")

            # Encode payload
            resp.payload = base64.b64encode(base_code.encode())
            resp.build_message = "Successfully built payload"

        except Exception as e:
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Build failed: {str(e)}"

        return resp