import os
import tiktoken
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

def query_openai(messages, tools = None, tool_choice = 'auto', model = 'gpt-3.5-turbo'):
    # 'gpt-4-turbo'
    # 'gpt-3.5-turbo'
    # 'gpt-4o-mini'

    client = OpenAI(api_key = os.environ.get('OPENAI_API_KEY'))
    response = client.chat.completions.create(
        messages = messages,
        model = model,
        tools = tools,
        tool_choice = tool_choice,
        temperature = 0
    )
    return response.choices[0].message


def calc_token(text, model = 'gpt-4-turbo'):
    # 'text-embedding-3-small'
    enc = tiktoken.get_encoding('cl100k_base')
    enc = tiktoken.encoding_for_model(model)
    return len(enc.encode(text))