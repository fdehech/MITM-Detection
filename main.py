import asyncio
import argparse
import sys
import os
import socket
import time
import re
import json
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scalar_fastapi import get_scalar_api_reference

app = FastAPI(
    title="MITM Detection System API",
    docs_url=None,
    redoc_url=None
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Helper Functions ---

def check_port(port: int) -> bool:
    """Check if a port is already in use on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.1)
        return s.connect_ex(('127.0.0.1', port)) == 0

def load_current_env() -> Dict[str, Any]:
    """Load current settings from .env file."""
    settings = {
        "use_proxy": True,
        "proxy_mode": "transparent",
        "delay_duration": 3.0,
        "max_delay": 2.0,
        "message_interval": 1.0,
        "payload": "HELLO",
        "detection_enabled": True
    }
    
    if not os.path.exists('.env'):
        return settings
        
    try:
        with open('.env', 'r') as f:
            content = f.read()
            
            # Check if proxy is enabled (heuristic based on port)
            if "CLIENT_PROXY_PORT=9001" in content:
                settings["use_proxy"] = False
            
            m = re.search(r"PROXY_MODE=(\w+)", content)
            if m: settings["proxy_mode"] = m.group(1)
            
            m = re.search(r"PROXY_DELAY_SECONDS=([\d.]+)", content)
            if m: settings["delay_duration"] = float(m.group(1))
            
            m = re.search(r"SERVER_MAX_DELAY=([\d.]+)", content)
            if m: settings["max_delay"] = float(m.group(1))
            
            m = re.search(r"CLIENT_MESSAGE_INTERVAL=([\d.]+)", content)
            if m: settings["message_interval"] = float(m.group(1))
            
            m = re.search(r"CLIENT_MESSAGE_PAYLOAD=(.+)", content)
            if m: settings["payload"] = m.group(1).strip()

            m = re.search(r"SERVER_DETECTION_ENABLED=(\w+)", content)
            if m: settings["detection_enabled"] = m.group(1).lower() == "true"
    except Exception:
        pass
        
    return settings

def update_env_file(config: Dict[str, Any]) -> None:
    """Update .env file with specified configuration."""
    use_proxy = config["use_proxy"]
    
    env_content = f"""# ========================================
# MITM Detection System - Configuration
# ========================================

# ----------------
# Client Settings
# ----------------
CLIENT_PROXY_HOST={'proxy' if use_proxy else 'server'}
CLIENT_PROXY_PORT={'9000' if use_proxy else '9001'}
CLIENT_MESSAGE_INTERVAL={config['message_interval']}
CLIENT_MESSAGE_PAYLOAD={config['payload']}

# ----------------
# Proxy Settings
# ----------------
PROXY_LISTEN_HOST=0.0.0.0
PROXY_LISTEN_PORT=9000
PROXY_SERVER_HOST=server
PROXY_SERVER_PORT=9001
PROXY_MODE={config['proxy_mode']}
PROXY_DELAY_SECONDS={config['delay_duration']}
PROXY_BUFFER_SIZE=4096

# ----------------
# Server Settings
# ----------------
SERVER_LISTEN_HOST=0.0.0.0
SERVER_LISTEN_PORT=9001
SERVER_MAX_DELAY={config['max_delay']}
SERVER_BUFFER_SIZE=4096
SERVER_DETECTION_ENABLED={'true' if config.get('detection_enabled', True) else 'false'}
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)

async def run_command(cmd: List[str]) -> str:
    """Run a shell command asynchronously and return stdout."""
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    
    if process.returncode != 0:
        raise Exception(f"Command failed: {stderr.decode().strip()}")
    
    return stdout.decode().strip()

async def check_docker() -> bool:
    """Check if Docker and docker-compose are available."""
    try:
        await run_command(["docker-compose", "--version"])
        await run_command(["docker", "info"])
        return True
    except:
        return False

# --- API Models ---

class ConfigModel(BaseModel):
    use_proxy: bool = True
    proxy_mode: str = "transparent"
    delay_duration: float = 3.0
    max_delay: float = 2.0
    message_interval: float = 1.0
    payload: str = "HELLO"
    detection_enabled: bool = True

# --- API Endpoints ---

@app.get("/docs", include_in_schema=False)
async def scalar_html():
    return get_scalar_api_reference(
        openapi_url=app.openapi_url,
        title=app.title,
        layout=Layout.CLASSIC,
        theme=Theme.DEEP_SPACE,
        hide_models=True,
        hide_client_button=False,
        show_sidebar=True,
        hide_search=False,
        hide_dark_mode_toggle=False,
        with_default_fonts=True,
        expand_all_model_sections=False,
        expand_all_responses=False,
        integration="fastapi"
    )

@app.get("/config")
async def get_config():
    """Get current configuration."""
    return load_current_env()

@app.post("/config")
async def post_config(config: ConfigModel):
    """Update configuration."""
    try:
        update_env_file(config.dict())
        return {"status": "success", "message": "Configuration updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simulation/start")
async def start_simulation(build: bool = False):
    """Start the simulation in detached mode."""
    if not await check_docker():
        raise HTTPException(status_code=500, detail="Docker or docker-compose not available")
    
    # Check for port conflicts
    ports_to_check = [9000, 9001]
    conflicts = [p for p in ports_to_check if check_port(p)]
    
    if conflicts:
        # Attempt cleanup
        try:
            await run_command(["docker-compose", "down"])
            await asyncio.sleep(1)
        except:
            pass
            
        if any(check_port(p) for p in ports_to_check):
            raise HTTPException(status_code=409, detail=f"Ports {conflicts} are busy")

    cmd = ["docker-compose", "up", "-d"]
    if build:
        cmd.append("--build")
    
    try:
        await run_command(cmd)
        return {"status": "success", "message": "Simulation started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start simulation: {str(e)}")

@app.post("/simulation/stop")
async def stop_simulation():
    """Stop the simulation."""
    try:
        await run_command(["docker-compose", "down"])
        return {"status": "success", "message": "Simulation stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop simulation: {str(e)}")

@app.get("/simulation/status")
async def get_status():
    """Get current status of simulation containers."""
    try:
        stdout = await run_command(["docker-compose", "ps", "--format", "json"])
        
        containers = []
        if stdout:
            # docker-compose ps --format json can return multiple objects (one per line)
            # or a single list depending on the version.
            try:
                # Try parsing as a single JSON list first
                raw_data = json.loads(stdout)
                if isinstance(raw_data, list):
                    containers_data = raw_data
                else:
                    containers_data = [raw_data]
            except json.JSONDecodeError:
                # Fallback: parse line by line
                containers_data = []
                for line in stdout.split('\n'):
                    if line.strip():
                        try:
                            containers_data.append(json.loads(line))
                        except:
                            continue
            
            for item in containers_data:
                # Map docker-compose fields to frontend fields
                name = item.get("Name") or item.get("Service") or "Unknown"
                state = item.get("State", "stopped").lower()
                status = item.get("Status", "Unknown")
                
                # Normalize state for frontend
                if "running" in state or "up" in state:
                    normalized_state = "running"
                elif "exit" in state or "stop" in state:
                    normalized_state = "stopped"
                else:
                    normalized_state = "error"
                
                containers.append({
                    "name": name,
                    "status": status,
                    "state": normalized_state
                })
        
        is_running = any(c["state"] == "running" for c in containers)
        
        return {
            "running": is_running,
            "containers": containers
        }
    except Exception as e:
        return {"running": False, "containers": [], "error": str(e)}

@app.get("/logs/{container_name}")
async def get_logs(container_name: str, tail: int = 100):
    """Get logs for a specific container."""
    try:
        # Use docker logs to fetch the last N lines
        # Note: docker logs sends to both stdout and stderr
        process = await asyncio.create_subprocess_exec(
            "docker", "logs", "--tail", str(tail), container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
             return {"logs": [f"Error fetching logs: {stderr.decode().strip()}"]}

        # Split into lines and filter empty ones
        lines = [line for line in stdout.decode().split('\n') if line.strip()]
        err_lines = [line for line in stderr.decode().split('\n') if line.strip()]
        
        # Combine and return
        all_logs = lines + err_lines
        
        return {"logs": all_logs}
    except Exception as e:
        return {"logs": [f"System error: {str(e)}"]}

@app.post("/simulation/reset")
async def reset_config():
    """Reset configuration to factory defaults."""
    factory_defaults = {
        "use_proxy": True,
        "proxy_mode": "transparent",
        "delay_duration": 3.0,
        "max_delay": 2.0,
        "message_interval": 1.0,
        "payload": "HELLO",
        "detection_enabled": True
    }
    update_env_file(factory_defaults)
    return {"status": "success", "message": "Reset to factory defaults"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
