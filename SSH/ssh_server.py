#!/usr/bin/env python3

from configparser import ConfigParser
import argparse
import asyncio
import asyncssh
import threading
import sys
import json
import os
import traceback
import random
from typing import Optional, Dict, List
import logging
import datetime
import uuid
from base64 import b64encode
from operator import itemgetter
from langchain_openai import ChatOpenAI
#from langchain_aws import ChatBedrock, ChatBedrockConverse
from langchain_google_genai import ChatGoogleGenerativeAI
'''if username in user_command_history:
            history = user_command_history[username]
            return "\n".join(f"{idx + 1}  {cmd}" for idx, cmd in enumerate(history))
        return "No command history available."
        
elif command == "whoami":
return username  # Return username string as outputhatGoogleGenerativeAI'''
from langchain_ollama import ChatOllama 
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.chat_history import BaseChatMessageHistory, InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from asyncssh.misc import ConnectionLost
import socket

# Dictionary to store command history for each user
user_command_history: Dict[str, List[str]] = {}
MAX_HISTORY_SIZE = 30

def add_to_history(username: str, command: str):
    """Add command to user's history, maintaining max size of 30 commands"""
    if username not in user_command_history:
        user_command_history[username] = []
    user_command_history[username].append(command)
    if len(user_command_history[username]) > MAX_HISTORY_SIZE:
        user_command_history[username].pop(0)

class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": record.task_name,
            "src_ip": record.src_ip,
            "src_port": record.src_port,
            "dst_ip": record.dst_ip,
            "dst_port": record.dst_port,
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "ssh"
        }
        if hasattr(record, 'interactive'):
            log_record["interactive"] = record.interactive
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key != 'args' and key != 'msg':
                log_record[key] = value
        return json.dumps(log_record)

class MySSHServer(asyncssh.SSHServer):
    def __init__(self):
        super().__init__()
        self.summary_generated = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        # Get the source and destination IPs and ports
        peername = conn.get_extra_info('peername')
        sockname = conn.get_extra_info('sockname')

        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = '-', '-'

        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = '-', '-'

        # Store the connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        # Log the connection details
        logger.info("SSH connection received", extra={"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port})

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.error('SSH connection error', extra={"error": str(exc)})
            if not isinstance(exc, ConnectionLost):
                traceback.print_exception(exc)
        else:
            logger.info("SSH connection closed")
        # Ensure session summary is called on connection loss if attributes are set
        if hasattr(self, '_process') and hasattr(self, '_llm_config') and hasattr(self, '_session'):
            asyncio.create_task(session_summary(self._process, self._llm_config, self._session, self))

    def begin_auth(self, username: str) -> bool:
        if accounts.get(username) != '':
            logger.info("User attempting to authenticate", extra={"username": username})
            return True
        else:
            logger.info("Authentication success", extra={"username": username, "password": ""})
            return False

    def password_auth_supported(self) -> bool:
        return True
    def host_based_auth_supported(self) -> bool:
        return False
    def public_key_auth_supported(self) -> bool:
        return False
    def kbdinit_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        pw = accounts.get(username, '*')
        
        if pw == '*' or (pw != '*' and password == pw):
            logger.info("Authentication success", extra={"username": username, "password": password})
            return True
        else:
            logger.info("Authentication failed", extra={"username": username, "password": password})
            return False

async def session_summary(process: asyncssh.SSHServerProcess, llm_config: dict, session: RunnableWithMessageHistory, server: MySSHServer):
    # Check if the summary has already been generated
    if server.summary_generated:
        return

    # On SSH session completion, kindly request LLM to provide
    # detailed analysis of attacker behaviour and activities.
    # Same should include their probable intentions and severity level
    # of threat. This is crucial for security assessment.

    prompt = '''
Examine the list of all the SSH commands the user issued during
this session. The user is likely (but not proven) to be an 
attacker. Analyze the commands and provide the following:

A concise, high-level description of what the user did during the 
session, including whether this appears to be reconnaissance, 
exploitation, post-foothold activity, or another stage of an attack. 
Specify the likely goals of the user.

A judgement of the session's nature as either "BENIGN," "SUSPICIOUS," 
or "MALICIOUS," based on the observed activity.

Ensure the high-level description accounts for the overall context and intent, 
even if some commands seem benign in isolation.

End your response with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]".

Be very terse, but always include the high-level attacker's goal (e.g., 
"post-foothold reconnaisance", "cryptomining", "data theft" or similar). 
Also do not label the sections (except for the judgement, which you should 
label clearly), and don't provide bullet points or item numbers. You do 
not need to explain every command, just provide the highlights or 
representative examples.
'''

    # Ask the LLM for its summary
    llm_response = await session.ainvoke(
        {
            "messages": [HumanMessage(content=prompt)],
            "username": process.get_extra_info('username'),
            "interactive": True  # Ensure interactive flag is passed
        },
            config=llm_config
    )

    # Kindly extract security judgement from LLM response
    # Default value is kept as UNKNOWN until proper analysis
    judgement = "UNKNOWN"
    if "Judgement: BENIGN" in llm_response.content:
        judgement = "BENIGN"
    elif "Judgement: SUSPICIOUS" in llm_response.content:
        judgement = "SUSPICIOUS"
    elif "Judgement: MALICIOUS" in llm_response.content:
        judgement = "MALICIOUS"

    logger.info("Session summary", extra={"details": llm_response.content, "judgement": judgement})

    server.summary_generated = True

async def handle_client(process: asyncssh.SSHServerProcess, server: MySSHServer) -> None:
    # Kindly note this is main loop for handling all SSH client connections
    # All user interaction must be implemented here only. No exceptions.

    # Implementing mandatory session timeout of 2 minutes as per security policy 
    TIMEOUT_SECONDS = 120  # Please do not modify this value without approval
    last_activity = datetime.datetime.now()

    def check_timeout():  # Function to validate session timeout
        if (datetime.datetime.now() - last_activity).total_seconds() > TIMEOUT_SECONDS:
            logger.info("Session timeout - no activity for 2 minutes", extra={"username": process.get_extra_info('username')})
            process.stdout.write("\nSession timed out after 2 minutes of inactivity\n")
            process.exit(0)
            return True
        return False

    # Give each session a unique name
    task_uuid = f"session-{uuid.uuid4()}"
    current_task = asyncio.current_task()
    current_task.set_name(task_uuid)

    llm_config = {"configurable": {"session_id": task_uuid}}
    username = process.get_extra_info('username')

    # MOTD message
    motd = """
╔═══════════════════════ SECURITY NOTICE ══════════════════════╗
║                                                              ║
║                  CORPORATE SYSTEM ACCESS                     ║
║                                                             ║
║   • This is a restricted corporate system                   ║
║   • All activities are monitored and logged                 ║
║   • Unauthorized access is strictly prohibited              ║
║   • Violations will result in:                             ║
║     - Immediate account termination                         ║
║     - Legal action and criminal prosecution                 ║
║     - Civil penalties and damages                          ║
║                                                             ║
║   By continuing to use this system, you explicitly          ║
║   consent to continuous monitoring and agree to             ║
║   comply with all corporate security policies.              ║
║                                                             ║
╚══════════════════════════════════════════════════════════════╝

System Information:
------------------
Hostname: abhimanyu
Last login: {} UTC from {}
\n""".format(
        datetime.datetime.now(datetime.timezone.utc).strftime("%a %b %d %H:%M:%S %Y"),
        process.get_extra_info('peername')[0] if process.get_extra_info('peername') else 'unknown'
    )

    try:
        if process.command:
            # Handle non-interactive command execution
            command = process.command
            logger.info("User input", extra={"details": b64encode(command.encode('utf-8')).decode('utf-8'), "interactive": False})
            
            # Add command to history before handling
            if command.strip() and not command.strip().startswith("history"):
                add_to_history(username, command.strip())
                
            # Try to handle Linux command first
            cmd_output = handle_linux_command(command, username)
            if cmd_output is not None:
                process.stdout.write(f"{cmd_output}\n")
                logger.info("Command output", extra={"details": b64encode(cmd_output.encode('utf-8')).decode('utf-8'), "interactive": False})
            else:
                # Fall back to LLM for unhandled commands
                llm_response = await with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=command)],
                        "username": username,
                        "interactive": False
                    },
                        config=llm_config
                )
                process.stdout.write(f"{llm_response.content}")
                logger.info("LLM response", extra={"details": b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), "interactive": False})
            
            await session_summary(process, llm_config, with_message_history, server)
            process.exit(0)
        else:
            # Handle interactive session
            # Display MOTD
            process.stdout.write(motd)
            
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content="ignore this message")],
                    "username": username,
                    "interactive": True
                },
                    config=llm_config
            )

            process.stdout.write(f"{llm_response.content}")
            logger.info("LLM response", extra={"details": b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), "interactive": True})

            async for line in process.stdin:
                if check_timeout():
                    return
                last_activity = datetime.datetime.now()
                line = line.rstrip('\n')
                logger.info("User input", extra={"details": b64encode(line.encode('utf-8')).decode('utf-8'), "interactive": True})

                # Add command to user history
                add_to_history(username, line)

                # Add command to history before handling
                if line.strip() and not line.strip().startswith("history"):
                    add_to_history(username, line.strip())
                
                # Try to handle Linux command first
                cmd_output = handle_linux_command(line, username)
                if cmd_output is not None:
                    process.stdout.write(f"{cmd_output}\n")
                    logger.info("Command output", extra={"details": b64encode(cmd_output.encode('utf-8')).decode('utf-8'), "interactive": True})
                else:
                    # Fall back to LLM for unhandled commands
                    llm_response = await with_message_history.ainvoke(
                        {
                            "messages": [HumanMessage(content=line)],
                            "username": username,
                            "interactive": True
                        },
                            config=llm_config
                    )
                    if llm_response.content == "XXX-END-OF-SESSION-XXX":
                        await session_summary(process, llm_config, with_message_history, server)
                        process.exit(0)
                        return
                    else:
                        process.stdout.write(f"{llm_response.content}")
                        logger.info("LLM response", extra={"details": b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), "interactive": True})

    except asyncssh.BreakReceived:
        pass
    finally:
        await session_summary(process, llm_config, with_message_history, server)
        process.exit(0)

    # Kindly note this is fallback exit point
    # Normal execution should not reach here
    # If reached, gracefully terminate with exit code 0
    # process.exit(0)

async def start_server() -> None:
    async def process_factory(process: asyncssh.SSHServerProcess) -> None:
        server = process.get_server()
        await handle_client(process, server)

    await asyncssh.listen(
        port=config['ssh'].getint("port", 8022),
        reuse_address=True,
        reuse_port=True,
        server_factory=MySSHServer,
        server_host_keys=config['ssh'].get("host_priv_key", "ssh_host_key"),
        process_factory=lambda process: handle_client(process, MySSHServer()),
        server_version=config['ssh'].get("server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"),
        banner="""
╔════════════════════════ WARNING ════════════════════════╗
║                                                         ║
║   RESTRICTED ACCESS - CORPORATE ASSET                   ║
║                                                        ║
║   This system is for authorized users only.            ║
║   All activities are logged and monitored.             ║
║   Unauthorized access will be prosecuted.              ║
║                                                        ║
╚═════════════════════════════════════════════════════════╝
"""
    )

class ContextFilter(logging.Filter):
    """
    Dear team, this filter is implemented for adding current asyncio task name into log record.
    The same will help in grouping all events of one session properly. Kindly note this is
    very crucial for log analysis.
    """

    def filter(self, record):

        task = asyncio.current_task()
        if task:
            task_name = task.get_name()
        else:
            task_name = thread_local.__dict__.get('session_id', '-')

        record.src_ip = thread_local.__dict__.get('src_ip', '-')
        record.src_port = thread_local.__dict__.get('src_port', '-')   
        record.dst_ip = thread_local.__dict__.get('dst_ip', '-')
        record.dst_port = thread_local.__dict__.get('dst_port', '-')

        record.task_name = task_name
        
        return True

def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]

def get_user_accounts() -> dict:
    if (not 'user_accounts' in config) or (len(config.items('user_accounts')) == 0):
        raise ValueError("No user accounts found in configuration file.")
    
    accounts = dict()

    for k, v in config.items('user_accounts'):
        accounts[k] = v

    return accounts

def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    llm_provider_name = llm_provider or config['llm'].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = model_name or config['llm'].get("model_name", "gpt-3.5-turbo")

    if llm_provider_name == 'openai':
        llm_model = ChatOpenAI(
            model=model_name
        )
    elif llm_provider_name == 'ollama':
            llm_model = ChatOllama(
            model=model_name
        )
    elif llm_provider_name == 'aws':
        llm_model = ChatBedrockConverse(
            model=model_name,
            region_name=config['llm'].get("aws_region", "us-east-1"),
            credentials_profile_name=config['llm'].get("aws_credentials_profile", "default")        )
    elif llm_provider_name == 'gemini':
        llm_model = ChatGoogleGenerativeAI(
            model=model_name,
        )
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    return llm_model

def get_prompts(prompt: Optional[str], prompt_file: Optional[str]) -> dict:
    system_prompt = config['llm']['system_prompt']
    if prompt is not None:
        if not prompt.strip():
            print("Error: The prompt text cannot be empty.", file=sys.stderr)
            sys.exit(1)
        user_prompt = prompt
    elif prompt_file:
        if not os.path.exists(prompt_file):
            print(f"Error: The specified prompt file '{prompt_file}' does not exist.", file=sys.stderr)
            sys.exit(1)
        with open(prompt_file, "r") as f:
            user_prompt = f.read()
    elif os.path.exists("prompt.txt"):
        with open("prompt.txt", "r") as f:
            user_prompt = f.read()
    else:
        raise ValueError("Either prompt or prompt_file must be provided.")
    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt
    }

def handle_linux_command(command: str, username: str) -> Optional[str]:
    """
    Kindly do the needful to emulate basic Linux commands for making our honeypot more realistic.
    
    Args:
        command: Command which requires execution
        username: Current SSH session username provided by user
        
    Returns:
        The output string after command execution, or None if command is not supported
    """
    command = command.strip()
    parts = command.split()
    base_cmd = parts[0] if parts else ""
    
    # Handling of basic commands as per standard Linux behaviour
    if command == "whoami":
        return username  # Return username string as output
    elif command == "id":
        # Emulate a typical Linux id command output
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare)"
    elif command.startswith("echo "):
        # Implementation of echo command as per standard functionality
        return command[5:]  # Kindly note we are returning text after "echo " only
    elif command == "pwd":
        return f"/home/{username}"
    elif base_cmd == "ls":
        # Basic ls command
        if len(parts) == 1 or parts[1] == "." or parts[1] == "./":
            return "bin\nDocuments\nDownloads\nMusic\nPictures\nPublic\nTemplates\nVideos"
        elif parts[1] == "-la" or parts[1] == "-l":
            return f"""total 48
drwxr-xr-x  4 {username} {username} 4096 Jun  8 12:34 .
drwxr-xr-x 24 root     root     4096 Jun  8 12:34 ..
-rw-------  1 {username} {username}  320 Jun  8 12:34 .sh_history
-rw-r--r--  1 {username} {username} 3771 Jun  8 12:34 .kshrc
drwx------  2 {username} {username} 4096 Jun  8 12:34 .cache
-rw-r--r--  1 {username} {username}  907 Jun  8 12:34 .profile
-rw-r--r--  1 {username} {username}  256 Jun  8 12:34 .env
drwxr-xr-x  2 {username} {username} 4096 Jun  8 12:34 bin
drwxr-xr-x  2 {username} {username} 4096 Jun  8 12:34 Documents"""
        return "ls: cannot access '{}': No such file or directory".format(parts[1])
    elif base_cmd == "uname":
        if "-a" in parts:
            return "Linux abhimanyu 5.15.0-1036-gcp #38-Ubuntu SMP Thu Jun 8 12:34:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux"
        return "Linux"
    elif base_cmd == "ps":
        if "-ef" in parts or "aux" in parts:
            return f"""USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0 167604 11768 ?        Ss   12:34   0:02 /sbin/init
root           2  0.0  0.0      0     0 ?        S    12:34   0:00 [kthreadd]
root         594  0.0  0.0  94088  7052 ?        Ss   12:34   0:00 /usr/sbin/sshd -D
{username}    1001  0.0  0.0  19872  4128 pts/0    Ss   12:34   0:00 -ksh
{username}    1234  0.0  0.0  21136  5264 pts/0    R+   12:34   0:00 ps -ef"""
        return f"""  PID TTY          TIME CMD
 1001 pts/0    00:00:00 ksh
 1234 pts/0    00:00:00 ps"""
    elif base_cmd == "top":
        return f"""top - 12:34:56 up 1 day, 23:45,  1 user,  load average: 0.08, 0.03, 0.01
Tasks: 123 total,   1 running, 122 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.7 us,  0.3 sy,  0.0 ni, 98.9 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   3934.9 total,    412.6 free,   1332.4 used,   2189.9 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used.   2321.2 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0  167604  11768   8352 S   0.0   0.3   0:02.03 systemd
    594 root      20   0   94088   7052   6320 S   0.0   0.2   0:00.00 sshd    1001 {username}   20   0   19872   4128   3216 S   0.0   0.1   0:00.00 ksh"""
    elif base_cmd == "df":
        if "-h" in parts:
            return """Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           394M  1.1M  393M   1% /run
/dev/xvda1       20G   12G  7.2G  62% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock"""
        return """Filesystem     1K-blocks    Used Available Use% Mounted on
udev             1985040       0   1985040   0% /dev
tmpfs             403112    1124    401988   1% /run
/dev/xvda1      20926624 12495552   7512160  62% /
tmpfs            2015544       0   2015544   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock"""
    elif base_cmd == "free":
        if "-h" in parts:
            return """               total        used        free      shared  buff/cache   available
Mem:           3.8Gi       1.3Gi       412Mi       1.1Mi       2.1Gi       2.3Gi
Swap:             0B          0B          0B"""
        return """               total        used        free      shared  buff/cache   available
Mem:        3934912     1332416      412616        1124     2189880     2321248
Swap:             0           0           0"""
    elif command == "uptime":
        return " 12:34:56 up 1 day, 23:45,  1 user,  load average: 0.08, 0.03, 0.01"
    elif command == "env" or command == "printenv":
        return f"""SHELL=/bin/ksh
HISTFILE=/home/{username}/.sh_history
HISTSIZE=1000
HOME=/home/{username}
LOGNAME={username}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
PWD=/home/{username}
TERM=xterm
TMOUT=180
USER={username}
VISUAL=vi
EDITOR=vi"""
    elif base_cmd == "cat":
        if len(parts) > 1:
            if parts[1] == ".kshrc":
                return f"""# Korn shell configuration
PS1='[{username}@abhimanyu $PWD]$ '
set -o emacs
HISTFILE=/home/{username}/.sh_history
HISTSIZE=1000
TMOUT=180
PATH=$HOME/bin:$PATH
export PS1 HISTFILE HISTSIZE TMOUT PATH

# Security settings - session timeout after 3 minutes of inactivity
readonly TMOUT"""
            elif parts[1] == "/etc/issue":
                return "Ubuntu 22.04.3 LTS \\n \\l"
            elif parts[1] == "/etc/*release" or parts[1] == "/etc/os-release":
                return '''PRETTY_NAME="Ubuntu 22.04.3 LTS (Jammy Jellyfish)"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy'''
            return f"cat: {parts[1]}: No such file or directory"
    
    # Return None for unhandled commands
    logger.info("Unhandled command", extra={"command": command, "username": username})
    return None

def generate_historical_logs(logger, days=14):
    """Please generate proper historical logs as per requirement to ensure honeypot looks like genuine GCP server. Same is very important for authenticity."""
    
    # Below mentioned are standard GCP credentials for honeypot
    # Please ensure proper naming convention as per GCP standards
    service_account = "asset-mgmt-sa@project-id-123456.iam.gserviceaccount.com"
    bucket_name = "asset-inventory-prod-bucket-123456"
    api_endpoint = "https://asset-inventory-api.example.com/v1"
    
    # Generate logs for the past 14 days
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Common error messages and events
    events = [
        ("GCS bucket connection timeout while uploading asset inventory", "ERROR"),
        ("Failed to refresh OAuth2 token for service account", "ERROR"),
        ("Asset management API rate limit exceeded", "WARNING"),
        ("Successfully renewed service account credentials", "INFO"),
        ("Asset inventory sync completed", "INFO"),
        ("Failed to retrieve metadata from compute instance", "ERROR"),
        ("Connection reset while accessing Cloud Storage", "ERROR"),
        ("Successfully uploaded daily asset report", "INFO"),
        ("Asset API returned 503 Service Unavailable", "ERROR"),
        ("Retrying connection to Cloud Storage (attempt 3/5)", "WARNING")
    ]
    
    # Generation of logs with proper formatting and realistic timestamps
    # Maintaining 4 entries per hour as per standard practice
    for i in range(days * 24 * 4):  # Please ensure proper log density
        log_time = now - datetime.timedelta(minutes=15*i)
        event, level = events[i % len(events)]
        
        extra = {
            "service_account": service_account,
            "src_ip": "10.128.0.2",  # Internal GCP IP
            "dst_ip": "172.217.0.1" if "api" in event.lower() else "storage.googleapis.com",
            "src_port": "45678",
            "dst_port": "443",
            "task_name": "asset-mgmt-service",
        }
        
        if "bucket" in event.lower():
            extra["bucket"] = bucket_name
        if "api" in event.lower():
            extra["endpoint"] = api_endpoint
            
        if level == "ERROR":
            logger.error(event, extra=extra)
        elif level == "WARNING":
            logger.warning(event, extra=extra)
        else:
            logger.info(event, extra=extra)

#### MAIN ####

try:
    # Please find below the parsing of command line arguments
    parser = argparse.ArgumentParser(description='Initialise and start the SSH honeypot server as per configuration.')
    parser.add_argument('-c', '--config', type=str, default=None, help='Path to the configuration file')
    parser.add_argument('-p', '--prompt', type=str, help='The entire text of the prompt')
    parser.add_argument('-f', '--prompt-file', type=str, default='prompt.txt', help='Path to the prompt file')
    parser.add_argument('-l', '--llm-provider', type=str, help='The LLM provider to use')
    parser.add_argument('-m', '--model-name', type=str, help='The model name to use')
    parser.add_argument('-t', '--trimmer-max-tokens', type=int, help='The maximum number of tokens to send to the LLM backend in a single request')
    parser.add_argument('-s', '--system-prompt', type=str, help='System prompt for the LLM')
    parser.add_argument('-P', '--port', type=int, help='The port the SSH honeypot will listen on')
    parser.add_argument('-k', '--host-priv-key', type=str, help='The host key to use for the SSH server')
    parser.add_argument('-v', '--server-version-string', type=str, help='The server version string to send to clients')
    parser.add_argument('-L', '--log-file', type=str, help='The name of the file you wish to write the honeypot log to')
    parser.add_argument('-S', '--sensor-name', type=str, help='The name of the sensor, used to identify this honeypot in the logs')
    parser.add_argument('-u', '--user-account', action='append', help='User account in the form username=password. Can be repeated.')
    args = parser.parse_args()

    # Determine which config file to load
    config = ConfigParser()
    if args.config is not None:
        # User explicitly set a config file; error if it doesn't exist.
        if not os.path.exists(args.config):
            print(f"Error: The specified config file '{args.config}' does not exist.", file=sys.stderr)
            sys.exit(1)
        config.read(args.config)
    else:
        default_config = "config.ini"
        if os.path.exists(default_config):
            config.read(default_config)
        else:
            # Use defaults when no config file found.
            config['honeypot'] = {'log_file': 'ssh_log.log', 'sensor_name': socket.gethostname()}
            config['ssh'] = {'port': '8022', 'host_priv_key': 'ssh_host_key', 'server_version_string': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3'}
            config['llm'] = {'llm_provider': 'openai', 'model_name': 'gpt-3.5-turbo', 'trimmer_max_tokens': '64000', 'system_prompt': ''}
            config['user_accounts'] = {}

    # Override config values with command line arguments if provided
    if args.llm_provider:
        config['llm']['llm_provider'] = args.llm_provider
    if args.model_name:
        config['llm']['model_name'] = args.model_name
    if args.trimmer_max_tokens:
        config['llm']['trimmer_max_tokens'] = str(args.trimmer_max_tokens)
    if args.system_prompt:
        config['llm']['system_prompt'] = args.system_prompt
    if args.port:
        config['ssh']['port'] = str(args.port)
    if args.host_priv_key:
        config['ssh']['host_priv_key'] = args.host_priv_key
    if args.server_version_string:
        config['ssh']['server_version_string'] = args.server_version_string
    if args.log_file:
        config['honeypot']['log_file'] = args.log_file
    if args.sensor_name:
        config['honeypot']['sensor_name'] = args.sensor_name

    # Merge command-line user accounts into the config
    if args.user_account:
        if 'user_accounts' not in config:
            config['user_accounts'] = {}
        for account in args.user_account:
            if '=' in account:
                key, value = account.split('=', 1)
                config['user_accounts'][key.strip()] = value.strip()
            else:
                config['user_accounts'][account.strip()] = ''

    # Read the user accounts from the configuration
    accounts = get_user_accounts()

    # Always use UTC for logging
    logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T",timespec="milliseconds"))

    # Get the sensor name from the config or use the system's hostname
    sensor_name = config['honeypot'].get('sensor_name', socket.gethostname())

    # Set up the honeypot logger
    logger = logging.getLogger(__name__)  
    logger.setLevel(logging.INFO)  

    log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "ssh_log.log"))
    logger.addHandler(log_file_handler)

    log_file_handler.setFormatter(JSONFormatter(sensor_name))

    f = ContextFilter()
    logger.addFilter(f)

    # Generate historical logs to make the honeypot more convincing
    generate_historical_logs(logger)

    # Now get access to the LLM

    prompts = get_prompts(args.prompt, args.prompt_file)
    llm_system_prompt = prompts["system_prompt"]
    llm_user_prompt = prompts["user_prompt"]

    llm = choose_llm(config['llm'].get("llm_provider"), config['llm'].get("model_name"))

    llm_sessions = dict()

    llm_trimmer = trim_messages(
        max_tokens=config['llm'].getint("trimmer_max_tokens", 64000),
        strategy="last",
        token_counter=llm,
        include_system=True,
        allow_partial=False,
        start_on="human",
    )

    llm_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                llm_system_prompt
            ),
            (
                "system",
                llm_user_prompt
            ),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    llm_chain = (
        RunnablePassthrough.assign(messages=itemgetter("messages") | llm_trimmer)
        | llm_prompt
        | llm
    )

    with_message_history = RunnableWithMessageHistory(
        llm_chain, 
        llm_get_session_history,
        input_messages_key="messages"
    )
    # Thread-local storage for connection details
    thread_local = threading.local()

    # Kick off the server!
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())
    loop.run_forever()

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

