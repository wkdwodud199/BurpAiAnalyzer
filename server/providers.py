"""
AI Provider abstraction layer.
Supports OpenAI, Anthropic, and Google Gemini.
"""
import logging
import json

logger = logging.getLogger(__name__)


class ProviderError(Exception):
    """Custom exception for provider errors."""
    pass


class BaseProvider:
    """Base class for AI providers."""

    def __init__(self, api_key, model):
        self.api_key = api_key
        self.model = model

    def chat(self, messages, temperature=0.3, max_tokens=4096):
        raise NotImplementedError


class OpenAIProvider(BaseProvider):
    """OpenAI API provider."""

    def __init__(self, api_key, model="gpt-4o"):
        super().__init__(api_key, model)
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key, timeout=300.0)

    def chat(self, messages, temperature=0.3, max_tokens=4096):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = response.choices[0].message.content
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
            logger.info("OpenAI [%s] tokens: %s", self.model, usage)
            return {"content": content, "usage": usage}
        except Exception as e:
            logger.error("OpenAI API error: %s", str(e))
            raise ProviderError("OpenAI: {}".format(str(e)))


class AnthropicProvider(BaseProvider):
    """Anthropic Claude API provider (API Key mode)."""

    def __init__(self, api_key, model="claude-sonnet-4-5-20250929"):
        super().__init__(api_key, model)
        import anthropic
        import httpx
        self.client = anthropic.Anthropic(
            api_key=api_key,
            timeout=httpx.Timeout(300.0, connect=30.0)
        )

    def chat(self, messages, temperature=0.3, max_tokens=4096):
        try:
            # Anthropic uses system param separately
            system_msg = ""
            chat_messages = []
            for m in messages:
                if m["role"] == "system":
                    system_msg = m["content"]
                else:
                    chat_messages.append(m)

            kwargs = {
                "model": self.model,
                "messages": chat_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if system_msg:
                kwargs["system"] = system_msg

            response = self.client.messages.create(**kwargs)
            content = response.content[0].text
            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            }
            logger.info("Anthropic [%s] tokens: %s", self.model, usage)
            return {"content": content, "usage": usage}
        except Exception as e:
            logger.error("Anthropic API error: %s", str(e))
            raise ProviderError("Anthropic: {}".format(str(e)))


class AnthropicOAuthProvider(BaseProvider):
    """Anthropic Claude provider using Claude Code SDK with OAuth token.

    Uses the claude_code_sdk which handles OAuth authentication internally.
    This bypasses the direct API limitation where OAuth is not supported.
    """

    def __init__(self, model="claude-sonnet-4-5-20250929"):
        super().__init__(api_key="", model=model)

    def _get_oauth_token(self):
        """Get valid OAuth token."""
        from oauth import get_valid_access_token
        token = get_valid_access_token()
        if not token:
            raise ProviderError("Anthropic OAuth: Not authenticated. Visit http://127.0.0.1:10512/auth/login to login.")
        return token

    def chat(self, messages, temperature=0.3, max_tokens=4096):
        import asyncio
        import os
        import time

        token = self._get_oauth_token()

        # Set OAuth token in environment for SDK
        os.environ["CLAUDE_CODE_OAUTH_TOKEN"] = token

        # Build prompt: combine system message and user messages
        system_msg = ""
        user_parts = []
        for m in messages:
            if m["role"] == "system":
                system_msg = m["content"]
            elif m["role"] == "user":
                user_parts.append(m["content"])
            elif m["role"] == "assistant":
                user_parts.append("[Previous AI response]\n{}".format(m["content"]))

        # Combine into a single prompt
        prompt = ""
        if system_msg:
            prompt = "{}\n\n---\n\n".format(system_msg)
        prompt += "\n\n".join(user_parts)

        start_time = time.time()

        try:
            content = self._run_sdk_query(prompt)
            elapsed = time.time() - start_time

            if not content:
                raise ProviderError("Anthropic OAuth SDK: Empty response")

            usage = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }
            logger.info("Anthropic OAuth SDK [%s] elapsed=%.1fs content_len=%d", self.model, elapsed, len(content))
            return {"content": content, "usage": usage}

        except ProviderError:
            raise
        except Exception as e:
            logger.error("Anthropic OAuth SDK error: %s", str(e))
            raise ProviderError("Anthropic OAuth SDK: {}".format(str(e)))

    def _run_sdk_query(self, prompt):
        """Run Claude Code SDK query, collecting text from AssistantMessages.

        Handles the rate_limit_event parse error gracefully by returning
        whatever text was collected before the error.
        """
        import asyncio
        from claude_code_sdk import query, ClaudeCodeOptions

        collected_text = []

        async def _query():
            try:
                async for msg in query(
                    prompt=prompt,
                    options=ClaudeCodeOptions(
                        model=self.model,
                        max_turns=10,
                    )
                ):
                    # Extract text from AssistantMessage content blocks
                    if hasattr(msg, 'content') and msg.content:
                        for block in msg.content:
                            if hasattr(block, 'text'):
                                collected_text.append(block.text)
            except Exception as e:
                # Handle rate_limit_event parse error gracefully
                # The response was already collected before this error
                error_name = type(e).__name__
                if "MessageParseError" in error_name or "rate_limit" in str(e).lower():
                    logger.debug("SDK stream ended with expected parse error: %s", str(e)[:100])
                else:
                    # Re-raise unexpected errors only if we have no content
                    if not collected_text:
                        raise

        # Run async query in sync context
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in an async context, create a new loop in a thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(asyncio.run, _query()).result(timeout=300)
            else:
                loop.run_until_complete(_query())
        except RuntimeError:
            # No event loop exists, create one
            asyncio.run(_query())

        return "\n".join(collected_text)


class GoogleProvider(BaseProvider):
    """Google Gemini API provider."""

    def __init__(self, api_key, model="gemini-2.0-flash"):
        super().__init__(api_key, model)
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self.genai = genai

    # Key instructions to reinforce in first user message,
    # since Gemini's system_instruction is less strictly followed in multi-turn.
    _REINFORCEMENT = (
        "[REMINDER: Respond with ONLY a single valid JSON object. "
        "No markdown fences, no text outside the JSON.]\n\n"
    )

    def chat(self, messages, temperature=0.3, max_tokens=4096):
        try:
            # Convert messages to Gemini format
            system_instruction = ""
            gemini_history = []
            last_user_msg = ""

            for m in messages:
                if m["role"] == "system":
                    system_instruction = m["content"]
                elif m["role"] == "user":
                    last_user_msg = m["content"]
                    # Don't add to history yet - last user msg goes to send_message
                elif m["role"] == "assistant":
                    gemini_history.append({"role": "model", "parts": [m["content"]]})

            # Reinforce key system instructions in user message for Gemini
            if system_instruction and "JSON" in system_instruction:
                last_user_msg = self._REINFORCEMENT + last_user_msg

            # Add all user messages except the last to history
            user_msgs = [m for m in messages if m["role"] == "user"]
            if len(user_msgs) > 1:
                gemini_history_with_users = []
                user_idx = 0
                for m in messages:
                    if m["role"] == "system":
                        continue
                    elif m["role"] == "user":
                        if user_idx < len(user_msgs) - 1:
                            gemini_history_with_users.append({"role": "user", "parts": [m["content"]]})
                        user_idx += 1
                    elif m["role"] == "assistant":
                        gemini_history_with_users.append({"role": "model", "parts": [m["content"]]})
                gemini_history = gemini_history_with_users

            gen_config = self.genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )

            model_kwargs = {"model_name": self.model, "generation_config": gen_config}
            if system_instruction:
                model_kwargs["system_instruction"] = system_instruction

            model = self.genai.GenerativeModel(**model_kwargs)
            chat = model.start_chat(history=gemini_history)
            response = chat.send_message(
                last_user_msg,
                request_options={"timeout": 300}
            )

            content = response.text
            usage = {
                "prompt_tokens": getattr(response, "usage_metadata", {}).get("prompt_token_count", 0) if hasattr(response, "usage_metadata") and response.usage_metadata else 0,
                "completion_tokens": getattr(response, "usage_metadata", {}).get("candidates_token_count", 0) if hasattr(response, "usage_metadata") and response.usage_metadata else 0,
                "total_tokens": 0,
            }
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                try:
                    usage["prompt_tokens"] = response.usage_metadata.prompt_token_count or 0
                    usage["completion_tokens"] = response.usage_metadata.candidates_token_count or 0
                    usage["total_tokens"] = usage["prompt_tokens"] + usage["completion_tokens"]
                except Exception:
                    pass

            logger.info("Google [%s] tokens: %s", self.model, usage)
            return {"content": content, "usage": usage}
        except Exception as e:
            logger.error("Google API error: %s", str(e))
            raise ProviderError("Google: {}".format(str(e)))


def create_provider(provider_name, api_key, model=None, auth_method="api_key"):
    """Factory function to create a provider instance.

    Args:
        provider_name: Provider name (openai, anthropic, google).
        api_key: API key (ignored for OAuth providers).
        model: Model name override.
        auth_method: "api_key" or "oauth".
    """
    default_models = {
        "openai": "gpt-4o",
        "anthropic": "claude-sonnet-4-5-20250929",
        "google": "gemini-2.0-flash",
    }

    if provider_name == "anthropic" and auth_method == "oauth":
        return AnthropicOAuthProvider(model=model or default_models["anthropic"])

    providers_map = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "google": GoogleProvider,
    }

    if provider_name not in providers_map:
        raise ProviderError("Unknown provider: {}. Available: {}".format(
            provider_name, list(providers_map.keys())
        ))

    cls = providers_map[provider_name]
    return cls(api_key=api_key, model=model or default_models.get(provider_name, ""))
