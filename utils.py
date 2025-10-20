import requests
import json

def ollama_one_shot():
    # Define the URL for the Ollama API's generate endpoint
    url = "http://localhost:11434/api/generate"

    # Define the payload for the request
    # This includes the model name and the prompt
    prompt = input("> ")
    payload = {
        "model": "gemma3:1b", 
        "prompt": prompt,
        "stream": False 
    }

    # headers for the request
    headers = {
        "Content-Type": "application/json"
    }

    try:
        # Send the POST request
        response = requests.post(url, json=payload, headers=headers)
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Parse the JSON response
            response_data = response.json()
            print("Ollama API Response:")
            print(response_data.get("response"))
            print(f"Error: Request failed with status code {response.status_code}")
            print(response.text)
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the Ollama server.")
        print("Please ensure Ollama is installed and running on http://localhost:11434.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def ollama_chat(prompt, stream=False):
    # List of dictionaries to hold the chat messages
    messages = [
        {"role": "system", "content": "You are a helpful AI assistant."},
        {"role": "user", "content": prompt}
    ]
    # Define the Ollama server URL (default is localhost:11434)
    ollama_url = "http://localhost:11434/api/chat"

    # Define the payload for the request
    # This includes the model to use and the chat messages
    payload = {
        "model": "gemma3:1b",  # Replace with the desired Ollama model
        "messages": messages,
        "stream": stream  # Set to True if you want streaming responses
    }

    # Set the headers for the request
    headers = {
        "Content-Type": "application/json"
    }

    try:
        # Send the POST request to the Ollama API
        # Using stream=True to handle potential streaming responses
        response = requests.post(ollama_url, headers=headers, data=json.dumps(payload), stream=stream)

        # Check if the request was successful
        response.raise_for_status()
        messages.append({"role": "assistant", "content": response})
        # Process the streamed response
        print("Ollama Response:")
        for line in response.iter_lines():
            if line:
                # Decode each line as JSON
                data = json.loads(line)
                # Extract and print the content from the message
                content = data.get("message", {}).get("content", "")
                print(content, end="", flush=True)
        if stream:
            print("\n") # Add a newline after the streamed response
    except requests.exceptions.RequestException as e:
        print(f"Error making request to Ollama: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            print(f"Response content: {e.response.text}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON response: {e}")
        print(f"Raw response content: {response.text}")
    return messages