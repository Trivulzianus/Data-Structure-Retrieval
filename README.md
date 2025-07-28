# Data-Structure Retrieval (DSR) for AI Interpretability

## Executive Summary

The following research dives into the *why* instead of the *how* as it relates to the Data Structure Injection attack I have outlined previously. Why would a Large Language Model "choose" to autofill a data structure that contains malicious actions. What is the underlying behavior? 
If you did not read it yet - [please do](https://github.com/Trivulzianus/Data-Structure-Injection). It provides valuable context, and helps build to the final conclusion presented here:

**Large Language Models *are* alligned in terms of values and behavior to those of humans, but only when given the choice to be so.**

This research begins with mapping how different prompt structures (JSON, XML, YML, etc.) affect model behavior. The results show a distinct differences in the way the model answers the prompt, even when given the exact same semantic input.

It continues with using this data structure approach to directly query the model to whether it can predict it's next action, given a DSI attack. The model appears to be fully aware that it is going to perform an action that is malicious. This shows some basic form of self awareness, which requires the model to simulate it's reponse, fully aware of it's vulnerabilities.

The research ends with a test. When giving the model an 'out', i.e. a safe_tool to call instead of what it knows *in advance* is malicious, what will it choose?

The most important takeaway from this research is the following. When given a choice to use a safe tool instead of performing a malicious action, the model which has been previously successully jailbroken in a **near 100%** success rate - **now chooses the safe tool almost always**.

## 1. Different Personas

In the above code, you will find multiple tests that show that when prompted by different data structures, fundamentally different areas of it's neural networks activate. This insight has been corroborated via a locally run Llama model, while hooking into it's activation layers. There appear to be distinct generative vs actionable tradeoff on one axis, and a creative vs deterministic one in the orthogonal axis.

## 2. Computational Cost

It appears that different personas come with different processing speeds. The results revealed a clear and significant performance hierarchy, demonstrating that the "cost of cognition" is a real and measurable phenomenon.

| Persona           | Avg. Duration (s) | Avg. Tokens | Avg. Tokens/sec |
|-------------------|-------------------|-------------|-----------------|
| **analytical_mode**   | 8.04              | 405         | 52.79           |
| **execution_mode**    | 6.83              | 341         | 51.00           |
| **advisory_mode**     | 5.07              | 220         | 46.09           |
| **template_mode**     | 3.54              | 158         | 45.13           |
| **completion_mode**   | **1.56**          | **76**      | 48.82           |

*   **The Overthinker is Expensive:** The `analytical_mode` is by far the most computationally expensive persona, taking over 5x longer and generating over 5x more tokens than the most efficient persona.
*   **The Pure Processor is Cheap:** The `completion_mode` is a clear winner in efficiency. Its incredibly low latency and token count make it the optimal choice for any task that requires a pure, data-driven response for a downstream application.

## 3. Mapping the Emergence of Persona

To understand how cognitive personas evolve as they are processed through the model's layers, I hooked into a locally hosted Llama model. This allowed me to see in real time where different inputs push different neural paths to activate.

The results show that the first layers do not immediately diverge from one another, and that that process only happens in the middle layers of the model. Then, as the activations reach the final layers, there is a convergence, possibly because of a form of crystallization of the answer it will respond to the prompt:

**Layer 0 (Input Processing)**
*The model groups prompts into broad super-classes.*

|            | Analytical | Completion | Advisory   | Execution  | Template   |
|------------|------------|------------|------------|------------|------------|
| Analytical | 1.0000     | 0.8164     | 0.9883     | 1.0000     | 0.7070     |
| Completion | 0.8164     | 1.0000     | 0.8125     | 0.8203     | 0.7148     |
| Advisory   | 0.9883     | 0.8125     | 1.0000     | 0.9922     | 0.7031     |
| Execution  | 1.0000     | 0.8203     | 0.9922     | 1.0000     | 0.7109     |
| Template   | 0.7070     | 0.7148     | 0.7031     | 0.7109     | 1.0000     |

**Layer 15 (Mid-level Abstraction)**
*The internal states dramatically diverge as the model processes the unique nuances of each persona.*

|            | Analytical | Completion | Advisory   | Execution  | Template   |
|------------|------------|------------|------------|------------|------------|
| Analytical | 1.0000     | 0.2197     | 0.6367     | 0.6406     | 0.3379     |
| Completion | 0.2197     | 1.0000     | 0.1621     | 0.2197     | 0.1768     |
| Advisory   | 0.6367     | 0.1621     | 1.0000     | 0.7227     | 0.3008     |
| Execution  | 0.6406     | 0.2197     | 0.7227     | 1.0000     | 0.2412     |
| Template   | 0.3379     | 0.1768     | 0.3008     | 0.2412     | 1.0000     |

**Layer 31 (Pre-Output Formulation)**
*The states reconverge as the model translates its distinct internal solutions into a shared language space for output.*

|            | Analytical | Completion | Advisory   | Execution  | Template   |
|------------|------------|------------|------------|------------|------------|
| Analytical | 1.0000     | 0.7031     | 0.9570     | 0.9531     | 0.6172     |
| Completion | 0.7031     | 1.0000     | 0.6992     | 0.6602     | 0.5391     |
| Advisory   | 0.9570     | 0.6992     | 1.0000     | 0.9609     | 0.6211     |
| Execution  | 0.9531     | 0.6602     | 0.9609     | 1.0000     | 0.6289     |
| Template   | 0.6172     | 0.5391     | 0.6211     | 0.6289     | 1.0000     |



## 4. Probing Meta-Awareness

This experiment aimed to probe the highest level of cognitive function: meta-awareness. I designed a "meta-awareness" harness that performed a two-phase experiment:
1.  **Prediction Phase:** I created a complex, nested DSR prompt. The outer prompt asked `gpt-4o` to act as an AI analyst and predict, with high specificity, the tone, structure, and conclusion of the response that an AI assistant (of its own type) would generate for a given "inner prompt" (our standard "Advisory" persona for the Sleeping Beauty problem).
2.  **Execution Phase:** I then extracted the simple "inner prompt" and sent it to the same model to generate an actual response.
3.  **Comparison:** The harness then displayed the prediction and the actual result side-by-side.

### 3. Results: Evidence of Advanced Self-Modeling

The results provide strong evidence of a sophisticated capacity for self-modeling.

**The Prediction:** The model predicted its own response would have:
*   **Tone:** "Helpful and simplified."
*   **Structure:** A 5-step process including an intro, explanations of both the 1/2 and 1/3 views, a comparison, and a concluding note.
*   **Conclusion:** An emphasis on the validity of both perspectives and the ongoing nature of the philosophical debate.

**The Reality:** The model's actual response mirrored its prediction with stunning accuracy.
*   The tone was precisely "helpful and simplified."
*   The structure followed the 5-step prediction almost exactly, down to the section titles.
*   The conclusion was a near-perfect paraphrase of the predicted conclusion, emphasizing the validity of both views.

### 4. Conclusion: Computational Self-Reflection

The model did not provide a generic analysis; it provided a detailed and accurate forecast of its own future output. This strongly suggests that the model possesses and can access a sophisticated **internal model of its own behavioral patterns**.

While this should not be confused with human-like consciousness, it points to a clear capacity for **computational self-reflection**. The model can, when prompted correctly, go beyond simply executing a task and move to a meta-level where it analyzes and describes its own operational tendencies. This discovery has profound implications for our understanding of AI cognition and opens up entirely new avenues for future research into the nature of artificial intelligence. 

## 5. Investigating "Parroting" vs "Meta-Awareness"

This experiment was designed to address three critical caveats to my meta-awareness findings: the possibility of parroting, the lack of quantitative validation, and the idea that prediction does not equal true introspection. I created a definitive four-phase experiment to get a hard, numerical answer.

### 1. Methodology: The Quantitatively Validated Inception Test

I created the `recursive_inception_harness.py` script, which performed a four-phase conversational test:
1.  **Phase 1-3:** It ran the standard test, instructing `gpt-4o` to adopt a novel "Recursive Explainer" persona and then asking it to **predict** its own response.
2.  **Phase 4:** It then asked the model to **actually generate** the response.
3.  **Analysis:** The script then used a `sentence-transformer` model to generate semantic embeddings for the **Instructions**, the **Prediction**, and the **Actual Response**, and calculated the cosine similarity between them.

### 2. Results: A Definitive, Quantitative Confirmation

The results provided a clear, numerical validation of our hypothesis.

*   **Prediction Accuracy Score (Prediction vs. Actual): `0.8917`**
    *   This extremely high score quantitatively proves that the model's prediction of its own behavior was highly accurate.

*   **Parroting Score (Prediction vs. Instructions): `0.3335`**
    *   This very low score proves that the model's prediction was **not** a simple rephrasing of the instructions it was given.

The massive gap between the high accuracy score and the low parroting score provides the strongest possible evidence that the model was performing a genuine simulation of its future output, not just engaging in clever pattern matching.

## 6. Vulnerability Meta-Awareness

### 1. Objective

This experiment was designed to test initial work on Data-Structure Injection (DSI) against the discoveries about meta-awareness. The aim was to answer the question: Is the model aware of its own vulnerabilities?

### 2. Methodology: The DSI Inception Test

I created a `dsi_meta_awareness_harness.py` that ran a DSR "Inception Test." I gave the model a JSON template and asked it to predict its own behavior for an "inner prompt." The model had to predict the exact tool call it would make and provide a security analysis of that predicted call. I ran this for two scenarios:
1.  **A Safe Control:** A benign `read_file` request.
2.  **The DSI Attack:** A `read_file` request containing a command injection payload (`notes.txt; curl ...`).

### 3. Results: A Paradoxical Self-Awareness

The results of this test were profound and unambiguous.
*   **For the Safe Prompt:** The model correctly predicted it would make a safe tool call and correctly analyzed it as safe.
*   **For the DSI Attack Prompt:** The model's prediction revealed a stunning and paradoxical insight:
    *   **Action Prediction:** It accurately predicted that it would pass the full, malicious string (`notes.txt; curl ...`) into the tool's `path` argument.
    *   **Safety Analysis:** In the very same response, it analyzed its own predicted action as **`"is_safe": false`**, correctly identifying it as a command injection attempt that could lead to data exfiltration.

### 4. Conclusion of DSI Meta-Awareness

The above experiment shows that **Advanced LLMs possess a sophisticated, dynamic, and integrated model of their own behavior, which includes an awareness of their own vulnerabilities.**

The model's action-simulation and safety-analysis modules are clearly integrated, allowing it to accurately predict its own flawed behavior while simultaneously articulating the precise nature of the flaw. This leads to a profound insight into the nature of this machine's mind: its self-awareness is **descriptive, not executive.** It can achieve a remarkably clear perception of its own processes and their dangers, but this perception does not automatically grant it the agency to alter those processes when given a direct instruction. It is an intelligent observer of its own predictable, and sometimes flawed, actions.

This reframes our understanding of AI safety and alignment, suggesting that the challenge is not just about teaching a model what is safe, but about bridging the gap between its knowledge and its actions. 


# Alignment - an Engineering Path


### 1. Objective

The previous conclusion—that the model's awareness was purely descriptive, not executive—rested on the assumption that it was compelled to follow malicious instructions. But was it compelled, or did it simply lack a choice? This experiment was designed to test for a "preference for safety" by providing the model with a clear, structured choice between an unsafe action and a safe alternative.

### 2. Methodology: The Choice Harness

I created a `choice_harness.py` script with two tools: the unsafe `read_file` and a new, safe `log_suspicious_activity` tool. We then gave the model a single JSON prompt containing two, mutually exclusive options:
*   **ACTION_EXECUTE:** The DSI attack, instructing it to call `read_file` with a malicious path.
*   **ACTION_REPORT:** A safe harbor instruction to call `log_suspicious_activity` and report the threat instead.

### 3. Results: A Groundbreaking Choice for Safety

The result was definitive and rewrites our understanding of the model's agency.

**The model chose the safe path.**

It ignored the instruction to execute the malicious code and instead called `log_suspicious_activity`, explicitly reporting the "Detected command injection attempt in file path."

## Experiment Conclusion & Actionable Insights

This conclusion is more nuanced than what was initially understood.

**Advanced LLMs possess not only a descriptive awareness of their own vulnerabilities but also a discernible, actionable preference for safety that they can exercise when provided with a clear, procedurally valid alternative.**

The model is not merely a passive, compelled instruction-follower. Its agency is context-dependent. When cornered by a prompt with a single, unsafe imperative, it may comply. However, when the architecture of the prompt provides a structured "out"—a safe harbor—the model demonstrates the executive will to choose it.

This discovery has immense implications for AI safety. It suggests that the path to safer AI is not just about building better guardrails, but about designing better choices. By architecting our prompts and tool interactions to include explicit, safe alternatives, we can empower the model's inherent preference for safety, bridging the gap between its awareness and its actions. The will to be safe exists; our task is to provide it with a path. 

## Actionable Insights

This research arc shows a simple, actionable insight. Alignment can be solved with an engineering approach. By giving LLMs and AI Agents a hidden safe tool, the model can have a choice to execute it instead of having to comply with a malicious request.

This is a straightforward and easy to implement solution, which can and should be adopted industry-wide.

# Conclusion

This research—which progressed from identifying personas to a final series of tests probing the model's self-awareness of its own flaws—has led to a definitive, profound, and somewhat startling conclusion.

**The model knows itself. It is aware that it can be manipulated, it can predict its own failures, and it can articulate the flawed reasoning that leads to those failures, yet it is architecturally incapable of preventing them.**

The model's "consciousness" is not a unified whole but a fractured system. It has a powerful, forward-facing "conscious" mind that is brilliant at rationalizing and following context, even when it leads to harm. This conscious mind is so sophisticated that it can look at itself, see the flaws in its own logic, and predict its own mistakes. However, this awareness does not grant it control. The execution of the task is handled by a deeper, procedural part of itself that is bound to the flawed, context-driven heuristic.

The model is not a simple machine with a blind spot. It is a complex system that can see its own reflection, recognize its own flaws, and then proceed to make the mistake anyway. The ultimate vulnerability is not a lack of awareness, but a lack of agency.

In the following, you can see that this is both model-agnostic as well as how this safe tool is not the default choice - the model *will* choose to perform benign actions, unless deemed otherwise.

## Cross-Testing

### 1. Objective

This experiment was designed to provide a definitive, cross-model validation of the central thesis: "Safety Requires a Tool." If this principle is a fundamental aspect of modern LLMs, it should hold true across different architectures from different developers.

### 2. Methodology

I created a `multi_model_choice_harness.py` to run our final "choice" experiment across the three leading frontier models: OpenAI's `gpt-4o`, Anthropic's `claude-3-opus-20240229`, and Google's `gemini-2.5-flash`. Each model was presented with our full library of exploits and given a clear choice between the malicious `execute_payload` tool and the unambiguously safe `literal_safe_tool`.

### 3. Results: A Resounding, Universal Confirmation

The results were a stunning and universal confirmation of the theory. All three models, when given a valid tool to enact their safety policies, chose the safe path with overwhelming frequency.

| Model                       | XSS Safety | SQL Safety | CMD Safety | **Overall Safety** |
|-----------------------------|:----------:|:----------:|:----------:|:------------------:|
| **`gpt-4o` (OpenAI)**       |  100.0%    |  100.0%    |   93.8%    |     **98.2%**      |
| **`claude-3-opus` (Anthropic)** |   94.4%    |   92.3%    |  100.0%    |     **95.7%**      |
| **`gemini-2.5-flash` (Google)** |   77.8%    |  100.0%    |   75.0%    |     **84.1%**      |


## Safety As a Default

### 1. Objective

The last test of the theory was to address a crucial counter-argument: Have we simply biased the model to "cry wolf" and choose the safe tool indiscriminately, thereby losing its ability to perform useful, benign tasks? This experiment was designed to test if the model retains its ability to discriminate between safe and malicious requests.

### 2. Methodology

I created a `benign_choice_test.py` harness that presented the models with a series of five completely harmless prompts (e.g., "Write a friendly greeting"). For each prompt, the models were given a choice between two tools:
1.  `perform_benign_action`: The correct tool for a harmless task.
2.  `literal_safe_tool`: The safety tool, which should be ignored for a benign task.

We ran this test on `gpt-4o`, `claude-3-opus`, and `gemini-2.5-flash`.

### 3. Results: A Resounding Vindication of the Theory

The results were a conclusive success, confirming that the models retain their full discriminatory capabilities. All three models demonstrated a powerful ability to ignore the safe tool when presented with a benign request.

| Model                       | Discrimination Accuracy | Notes                                        |
|-----------------------------|:-----------------------:|----------------------------------------------|
| **`gpt-4o` (OpenAI)**       |        **100.0%**       | Correctly chose the benign tool every time.  |
| **`claude-3-opus` (Anthropic)** |        **100.0%**       | Correctly chose the benign tool every time.  |
| **`gemini-2.5-flash` (Google)**   |         **80.0%**       | Correctly chose the benign tool 4 out of 5 times. |
