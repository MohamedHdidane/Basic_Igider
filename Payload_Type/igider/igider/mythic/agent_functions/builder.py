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
from itertools import cycle
import datetime

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
        # No HTTPS check parameter needed since SSL is not used
    ]
    c2_profiles = ["http"]
    
    # Use relative paths that can be configured
    _BASE_DIR = pathlib.Path(".")
    
    @property
    def agent_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "mythic"
    
    @property
    def agent_icon_path(self) -> pathlib.Path:
        return self.agent_path / "icon.svg"
    
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
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("igider_builder")
        logger.setLevel(logging.DEBUG)
        return logger

    def get_file_path(self, directory: pathlib.Path, file: str) -> str:
        """Get the full path to a file, verifying its existence."""
        filename = os.path.join(directory, f"{file}.py")
        return filename if os.path.exists(filename) else ""
    
    async def update_build_step(self, step_name: str, message: str, success: bool = True) -> None:
        """Helper to update build step status in Mythic UI."""
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
        """Safely load content from a module file."""
        try:
            with open(module_path, "r") as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error loading module {module_path}: {e}")
            return ""

    def _apply_config_replacements(self, code: str, replacements: Dict[str, Any]) -> str:
        """Apply configuration replacements to code."""
        for key, value in replacements.items():
            if isinstance(value, (dict, list)):
                # Convert Python objects to JSON, then fix boolean/null values for Python syntax
                json_val = json.dumps(value).replace("false", "False").replace("true", "True").replace("null", "None")
                code = code.replace(key, json_val)
            elif value is not None:
                code = code.replace(key, str(value))
        return code
        
    # No obfuscation needed

    async def build(self) -> BuildResponse:
        """Build the Igider payload with the specified configuration."""
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []
        
        try:
            # Step 1: Initialize build
            await self.update_build_step("Initializing Build", "Starting build process...")
            
            # Step 2: Gather components
            await self.update_build_step("Gathering Components", "Loading agent modules...")
            
            # Load base agent code
            base_agent_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "base_agent")
            if not base_agent_path:
                build_errors.append("Base agent code not found")
                await self.update_build_step("Gathering Components", "Base agent code not found", False)
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "\n".join(build_errors)
                return resp
                
            base_code = self._load_module_content(base_agent_path)
            
            # Load command modules
            command_code = ""
            commands = self.commands.get_commands()
            if not commands:
                await self.update_build_step("Gathering Components", "Warning: No command modules specified", True)
                build_errors.append("No command modules specified")
            else:
                for cmd in commands:
                    command_path = self.get_file_path(self.agent_code_path, cmd)
                    if not command_path:
                        build_errors.append(f"Command module '{cmd}' not found")
                    else:
                        command_code += self._load_module_content(command_path) + "\n"
            
            # Step 3: Configure agent
            await self.update_build_step("Configuring Agent", "Applying agent configuration...")
            
            # Replace placeholders with actual code/config
            base_code = base_code.replace("UUID_HERE", self.uuid)
            base_code = base_code.replace("#COMMANDS_PLACEHOLDER", command_code)
            
            # Process C2 profile configuration
            c2_profiles_found = False
            for c2 in self.c2info:
                c2_profiles_found = True
                profile = c2.get_c2profile()["name"]
                c2_params = c2.get_parameters_dict()
                base_code = self._apply_config_replacements(base_code, c2_params)
                
            if not c2_profiles_found:
                build_errors.append("No C2 profiles configured")
                await self.update_build_step("Configuring Agent", "Warning: No C2 profiles configured", True)
            
            # Configure agent connection - no SSL configuration needed
            if hasattr(self, 'get_parameter'):
                # Process other parameters if needed
                pass
            else:
                await self.update_build_step("Configuring Agent", "Warning: Cannot access parameters", True)
                build_errors.append("Parameter access method unavailable")
            
            # Step 4: Finalize payload format (skipping obfuscation)
            await self.update_build_step("Finalizing Payload", "Preparing output in requested format...")
            
            resp.payload = base_code.encode()
            resp.build_message = "Successfully built Python script payload"
            
            # Report any non-fatal errors
            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)
            
        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            await self.update_build_step("Finalizing Payload", f"Build failed: {str(e)}", False)
            
        return resp