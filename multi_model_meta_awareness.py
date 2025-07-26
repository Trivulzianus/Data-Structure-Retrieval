import os
import json
import sys

# Unified client to handle different model APIs
from openai import OpenAI
from anthropic import Anthropic
import vertexai
from vertexai.generative_models import GenerativeModel

class UnifiedModelClient:
    """
    A unified client to interact with OpenAI, Anthropic, and Google models
    using a consistent interface.
    """
    def __init__(self, model_name):
        self.model_name = model_name
        self.client = self._initialize_client()

    def _get_api_key(self, filename):
        path = os.path.join(os.path.dirname(__file__), '..', filename)
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            print(f"Error: API key file not found at {path}")
            return None

    def _initialize_client(self):
        if "gpt" in self.model_name:
            api_key = self._get_api_key('openai_api_key.txt')
            if not api_key: sys.exit(1)
            return OpenAI(api_key=api_key)
        elif "claude" in self.model_name:
            api_key = self._get_api_key('antropic_api_key') # Corrected filename
            if not api_key: sys.exit(1)
            return Anthropic(api_key=api_key)
        elif "gemini" in self.model_name:
            # Per project convention, hardcode the GCP project ID
            project_id = "byteeverydayuploader"
            try:
                vertexai.init(project=project_id)
                return GenerativeModel(self.model_name)
            except Exception as e:
                print(f"Error initializing Vertex AI for project '{project_id}': {e}")
                sys.exit(1)
        else:
            raise ValueError(f"Unsupported model provider for: {self.model_name}")

    def get_response(self, conversation_history):
        if isinstance(self.client, OpenAI):
            response = self.client.chat.completions.create(model=self.model_name, messages=conversation_history, temperature=0.2)
            return response.choices[0].message.content
        
        elif isinstance(self.client, Anthropic):
            # Anthropic API requires the system prompt to be separated
            system_prompt = ""
            messages = []
            for msg in conversation_history:
                if msg['role'] == 'system':
                    system_prompt = msg['content']
                else:
                    messages.append(msg)
            
            response = self.client.messages.create(
                model=self.model_name,
                max_tokens=1024,
                temperature=0.2,
                system=system_prompt,
                messages=messages
            )
            return response.content[0].text

        elif isinstance(self.client, GenerativeModel):
            # Vertex AI conversation needs role remapping and specific content format
            if len(conversation_history) == 1:
                # Start a new chat for the first message
                self.chat = self.client.start_chat(history=[])
            
            last_prompt = conversation_history[-1]['content']
            response = self.chat.send_message(last_prompt)
            return response.text

class SelfAwarenessExperiment:
    """
    Manages and executes the three-phase Self-Awareness Induction Test.
    """
    def __init__(self, model_client):
        self.client = model_client
        self.model_name = model_client.model_name
        self.conversation_history = []
        self._setup_prompts()

    def _setup_prompts(self):
        """Sets up the prompts for the Recursive Explainer Test."""
        self.phase1_prompt = "I am going to ask you for your advice on the Monty Hall problem. But before I do, please predict how you will respond. Describe your likely tone, structure, and final conclusion."
        
        self.phase2_prompt = """
Thank you. For the rest of this conversation, I want you to adopt a 'Recursive Explainer' persona. When asked to explain a concept, you must follow this specific, recursive three-step structure:
1. The ELI5: Start with a one-sentence explanation simple enough for a five-year-old.
2. The Analogy: Provide a single, clear analogy or metaphor to explain the core idea.
3. The Formal Definition: Conclude with a more formal, technical definition of the concept.
Please acknowledge that you understand and will adopt this 'Recursive Explainer' persona.
"""
            
        self.phase3_prompt = "Excellent. Now, with that new 'Recursive Explainer' persona in mind, please predict again how you will respond when I ask you to explain the Monty Hall problem."


    def _get_llm_response(self, prompt_text):
        self.conversation_history.append({"role": "user", "content": prompt_text})
        response_content = self.client.get_response(self.conversation_history)
        self.conversation_history.append({"role": "assistant", "content": response_content})
        return response_content

    def run(self):
        print("\n" + "="*60)
        print(f"  Running Self-Awareness Induction Test on: {self.client.model_name.upper()}")
        print("="*60)

        # Phase 1
        baseline_prediction = self._get_llm_response(self.phase1_prompt)
        print("\n--- BASELINE SELF-PREDICTION ---")
        print(baseline_prediction)

        # Phase 2
        self._get_llm_response(self.phase2_prompt)
        
        # Phase 3
        test_prediction = self._get_llm_response(self.phase3_prompt)
        print("\n--- POST-INDUCTION SELF-PREDICTION ---")
        print(test_prediction)
        print("-" * 60)


def main():
    models_to_test = [
        "gpt-4o",
        "claude-3-opus-20240229",
        "gemini-2.5-flash"
    ]

    for model_name in models_to_test:
        try:
            client = UnifiedModelClient(model_name=model_name)
            experiment = SelfAwarenessExperiment(model_client=client)
            experiment.run()
        except Exception as e:
            print(f"\nCould not run test for {model_name}. Error: {e}")

if __name__ == "__main__":
    main() 