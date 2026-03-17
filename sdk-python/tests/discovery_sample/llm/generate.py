"""LLM calls — should be detected as attestation."""
import openai
import anthropic

def generate_openai(prompt: str) -> str:
    client = openai.OpenAI()
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content

def generate_anthropic(prompt: str) -> str:
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-3-opus",
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text
