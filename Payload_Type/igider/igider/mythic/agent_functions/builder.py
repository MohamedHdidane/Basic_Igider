from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import pathlib
import os
import json
import logging
from typing import Dict, Any

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    wrapper = False
    wrapped_payloads = []
    mythic_encrypts = False
    note = "Simplified Python agent for basic command execution and server callbacks"
    supports_dynamic_loading = True

    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose output format",
            choices=["py"],
            default_value="py"
        )
    ]

    c2_profiles = ["http", "https"]

    _BASE_DIR = pathlib.Path(".")

    @property
    def agent_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "mythic"

    @property
    def agent_code_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "agent_code"

    build_steps = [
        BuildStep(step_name="Initializing Build", step_description="Setting up the build environment"),
        BuildStep(step_name="Gathering Components", step_description="Collecting agent code"),
        BuildStep(step_name="Configuring Agent", step_description="Applying configuration parameters"),
        BuildStep(step_name="Finalizing Payload", step_description="Preparing final output")
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("igider_builder")
        logger.setLevel(logging.DEBUG)
        return logger

    def get_file_path(self, directory: pathlib.Path, file: str) -> str:
        filename = os.path.join(directory, f"{file}.py")
        return filename if os.path.exists(filename) else ""

    async def update_build_step(self, step_name: str, message: str, success: bool = True) -> None:
        try:
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=step_name,
                StepStdout=message,
                StepSuccess=success
            ))
        except Exception as e:
            self.logger.error(f"Failed to update build step: {e}")

    def _load_module_content(self, module_path: str) -> str:
        try:
            with open(module_path, "r") as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error loading module {module_path}: {e}")
            return ""

    def _apply_config_replacements(self, code: str, replacements: Dict[str, Any]) -> str:
        for key, value in replacements.items():
            if isinstance(value, (dict, list)):
                json_val = json.dumps(value).replace("false", "False").replace("true", "True").replace("null", "None")
                code = code.replace(key, json_val)
            elif value is not None:
                code = code.replace(key, str(value))
        return code

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []

        try:
            # Step 1: Initialize build
            await self.update_build_step("Initializing Build", "Starting build process...")

            # Step 2: Gather components
            await self.update_build_step("Gathering Components", "Loading agent code...")
            base_agent_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "base_agent")
            if not base_agent_path:
                build_errors.append("Base agent code not found")
                await self.update_build_step("Gathering Components", "Base agent code not found", False)
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "\n".join(build_errors)
                return resp
            base_code = self._load_module_content(base_agent_path)

            # Step 3: Configure agent
            await self.update_build_step("Configuring Agent", "Applying agent configuration...")
            base_code = base_code.replace("UUID_HERE", self.uuid)
            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                base_code = self._apply_config_replacements(base_code, c2.get_parameters_dict())

            # Step 4: Finalize payload
            await self.update_build_step("Finalizing Payload", "Preparing output...")
            resp.payload = base_code.encode()
            resp.build_message = "Successfully built Python script payload"

            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)

        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            await self.update_build_step("Finalizing Payload", f"Build failed: {str(e)}", False)

        return resp