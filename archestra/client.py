import os
import json
import httpx
import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import HTTPException

logger = logging.getLogger(__name__)

class ArchestraClient:
    """
    Client for interacting with the Archestra AI Orchestration Platform
    via the A2A (Agent-to-Agent) JSON-RPC protocol.
    """
    
    def __init__(self, base_url: Optional[str] = None, project: Optional[str] = None, 
                 api_key: Optional[str] = None, agent_id: Optional[str] = None):
        self.base_url = base_url or os.getenv("ARCHESTRA_API_URL", "http://archestra:9000")
        self.project = project or os.getenv("ARCHESTRA_PROJECT", "backend-lucid")
        self.api_key = api_key or os.getenv("ARCHESTRA_API_KEY")
        self.agent_id = agent_id or os.getenv("ARCHESTRA_AGENT_ID")
        self.timeout = httpx.Timeout(120.0, connect=10.0)
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer archestra_77d1f898631520152b31283377a2ed13",
        }

    async def execute_agent(self, agent_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a single agent on Archestra via the A2A protocol.
        
        Args:
            agent_name: Name of the agent to execute.
            payload: Input payload for the agent.
            
        Returns:
            The agent's output.
            
        Raises:
            HTTPException: If the call fails or validation fails.
        """
        url = f"{self.base_url}/api/v1/agents/{agent_name}/execute"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers) as client:
                response = await client.post(
                    url, 
                    json={
                        "project": self.project,
                        "payload": payload
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Archestra API error for agent {agent_name}: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=f"Archestra API invalid response: {e.response.text}")
        except httpx.RequestError as e:
            logger.error(f"Archestra connection error: {e}")
            raise HTTPException(status_code=503, detail=f"Could not connect to Archestra: {str(e)}")

    async def execute_workflow(self, workflow_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a workflow on Archestra.
        """
        pass

    async def call_llm(self, 
                       system_prompt: str, 
                       user_prompt: str, 
                       json_schema: Optional[Dict[str, Any]] = None,
                       temperature: float = 0.0) -> Dict[str, Any]:
        """
        Execute an LLM call via Archestra's A2A (Agent-to-Agent) JSON-RPC endpoint.
        
        Sends a message/send JSON-RPC request combining system and user prompts,
        then extracts and parses the response text from the A2A message parts.
        
        Args:
            system_prompt: The system instruction.
            user_prompt: The user input.
            json_schema: Optional JSON schema for structured output enforcement.
            temperature: LLM temperature (included in message context).
            
        Returns:
            Parsed JSON output or text response dict.
        """
        if not self.agent_id:
            raise HTTPException(
                status_code=500, 
                detail="ARCHESTRA_AGENT_ID not configured. Set it in environment variables."
            )

        url = f"{self.base_url}/v1/a2a/{self.agent_id}"
        
        # Build the combined message text with system + user prompts
        message_text = f"[System Instructions]\n{system_prompt}\n\n[User Request]\n{user_prompt}"
        
        # Add JSON schema instruction if provided
        if json_schema:
            schema_str = json.dumps(json_schema, indent=2)
            message_text += f"\n\n[Response Format]\nReturn ONLY valid JSON matching this schema:\n{schema_str}"

        # Build JSON-RPC 2.0 request using A2A message/send method
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "parts": [
                        {"kind": "text", "text": message_text}
                    ]
                }
            }
        }

        max_retries = 3
        base_delay = 2.0
        last_result = None
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Calling Archestra A2A agent at {url} (attempt {attempt + 1}/{max_retries})")
                async with httpx.AsyncClient(timeout=self.timeout, headers=self.headers) as client:
                    response = await client.post(url, json=rpc_payload)
                    response.raise_for_status()
                    
                    rpc_response = response.json()
                    
                    # Handle JSON-RPC error responses
                    if "error" in rpc_response:
                        error = rpc_response["error"]
                        error_msg = error.get("message", "Unknown A2A error")
                        logger.error(f"A2A JSON-RPC error: {error_msg}")
                        raise HTTPException(status_code=500, detail=f"Archestra A2A error: {error_msg}")
                    
                    # Extract text from A2A response parts
                    parsed = self._parse_a2a_response(rpc_response)
                    last_result = parsed
                    
                    # Check if the response is empty/useless (LLM returned empty text due to 503)
                    is_empty = (
                        not parsed or
                        (isinstance(parsed, dict) and parsed.get("raw") is True) or
                        (isinstance(parsed, dict) and "messageId" in parsed and 
                         not any(k for k in parsed.keys() if k not in ("messageId", "role", "parts", "raw_response")))
                    )
                    
                    if is_empty and attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(f"A2A returned empty/unusable response, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                        await asyncio.sleep(delay)
                        continue
                    
                    return parsed
                    
            except httpx.HTTPStatusError as e:
                logger.error(f"Archestra A2A error: {e.response.text}")
                # Handle 429 (Too Many Requests) and 503 (Service Unavailable) with backoff
                if e.response.status_code in (429, 503) and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    reason = "Rate Limited" if e.response.status_code == 429 else "Service Unavailable"
                    logger.warning(f"{reason} (429/503), retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                    await asyncio.sleep(delay)
                    continue
                
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"Retrying A2A call in {delay}s after HTTP error {e.response.status_code}")
                    await asyncio.sleep(delay)
                    continue

                raise HTTPException(
                    status_code=e.response.status_code, 
                    detail=f"Archestra A2A failure: {e.response.text}"
                )
            except httpx.RequestError as e:
                logger.error(f"Archestra connection error: {e}")
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"Retrying A2A call in {delay}s after connection error")
                    await asyncio.sleep(delay)
                    continue
                raise HTTPException(
                    status_code=503, 
                    detail=f"Could not connect to Archestra A2A endpoint: {str(e)}"
                )
        
        # Should not reach here, but return last result as fallback
        return last_result or {}

    def _parse_a2a_response(self, rpc_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse A2A JSON-RPC response and extract the result.
        
        Looks for text parts in the response message and attempts to parse
        them as JSON. Falls back to returning raw text in a dict.
        """
        result = rpc_response.get("result", {})
        
        # Log raw structure for debugging
        if isinstance(result, dict):
            logger.info(f"A2A response keys: {list(result.keys())}")
        
        # The A2A result may contain a message with parts
        # Try multiple possible response structures
        parts = []
        
        # Standard A2A: result.artifacts[].parts
        if isinstance(result, dict) and "artifacts" in result:
            artifacts = result["artifacts"]
            if isinstance(artifacts, list):
                for artifact in artifacts:
                    if isinstance(artifact, dict) and "parts" in artifact:
                        parts.extend(artifact["parts"])
        
        # Direct result.parts
        if not parts and isinstance(result, dict) and "parts" in result:
            parts = result["parts"]
        # result.message.parts 
        if not parts and isinstance(result, dict) and "message" in result:
            msg = result["message"]
            if isinstance(msg, dict) and "parts" in msg:
                parts = msg["parts"]
        # result.content[].parts
        if not parts and isinstance(result, dict) and "content" in result:
            content = result["content"]
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and "parts" in item:
                        parts.extend(item["parts"])
        # result.status.message.parts (some A2A implementations)
        if not parts and isinstance(result, dict) and "status" in result:
            status = result["status"]
            if isinstance(status, dict) and "message" in status:
                msg = status["message"]
                if isinstance(msg, dict) and "parts" in msg:
                    parts.extend(msg["parts"])
        
        # Extract text from all text parts
        text_parts = []
        for part in parts:
            if isinstance(part, dict) and part.get("kind") == "text":
                text_parts.append(part.get("text", ""))
        
        combined_text = "\n".join(text_parts).strip()
        
        if not combined_text:
            # If no text parts found, log the full structure for debugging and return raw result
            logger.warning(f"No text parts found in A2A response. Result structure: {json.dumps(result, default=str)[:500]}")
            return result if isinstance(result, dict) else {"raw_response": result}
        
        # Try to parse the text as JSON (agents expect JSON responses)
        try:
            # Handle case where JSON is wrapped in markdown code blocks
            clean_text = combined_text
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.startswith("```"):
                clean_text = clean_text[3:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            clean_text = clean_text.strip()
            
            return json.loads(clean_text)
        except (json.JSONDecodeError, ValueError):
            # Return raw text wrapped in a dict if it's not valid JSON
            logger.info("A2A response is not JSON, returning as text")
            return {"text": combined_text, "raw": True}
