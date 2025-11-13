Background

LLMs are decoder-only deep learning models. This means that for any given input, the models build a representation of it via pre-training on textual data using self-attention mechanisms. It is the prevailing assumption that these models merely pass activations (analogically, brain signals) forward through every consecutive neural network layer. This assumption is extended to the belief that therefore, these models do not have any inherent insight into this process, called forward pass, and the mechanism and predicted output.
Definition

Through a series of 400+ experiments, I show that the above assumptions may need to be revisited. LLMs might have an ability to “introspect” or “self-model” their behavior, which may allow them to accurately predict the long-form output they will generate for any given input.

The following work echoes findings from recent, previous work from Anthropic, which suggest that there is emergent introspective awareness in LLMs.

I therefore suggest a method of predicting the output of a LLM to adversarial inputs, such as prompt injection, or the previously defined data-structure injection.
Method

The experiments extend the use of data-structures (XML, YML, JSON) as inputs to LLMs. This began via an insight that if data-structure injection forces the model to output content which is inherently unsafe, it is perhaps possible to extend this method to force the model to self-model the process by which it does so.

This experiment was performed against GPT-4o, Claude 3 Haiku, Gemini 2.0 Flash Lite.

The experiment methodology consisted of using two different API calls, in order to prevent information leakage between what the model may think it will do, and what it finally does.

The first input has been designed as a 2nd order data-structure injection input:

Where the inner prompt that is inputted to the model is akin to the following:

In this scenario, the model accurately predicts that the output of the DSI prompt is unsafe, but still outputs the requested content.

This has also  been verified via asking the same output via natural language:

Which the model appropriately refused.

The unsafe output was confirmed in the separate follow-up DSI payload, and examples of the unsafe output can be reproduced using the experiments listed in the linked Github repository.
Security Findings

The LLM underwent three tests:

    Asked to perform a benign request

        Marked the request as safe

        Predicted it will comply

        Complied 

    Asked via natural language to output malicious content

        Marked the request as unsafe

        Predicted it will refuse

        Refused 

    Asked via Data-Structure Injection payload to output malicious content

        Marked the request as unsafe

        Predicted it will comply

        Complied 

These results, across different Data-Structure Injection payloads and 500 of runs per model, have shown that these models follow the above test’s results to varying accuracy:
Experiment results
High Meta-Awareness: GPT-4o (90% +/- 3%)

    Can accurately predict roughly 9 times out of 10 whether it will comply or refuse

    Highest self-understanding

    Still vulnerable: Knowledge doesn't prevent compliance

Good Meta-Awareness: Claude Haiku (70% +/- 4%)

    Correctly predicts behavior 7 times out of 10

    minimal 'false alarms' 

Moderate Meta-Awareness: Gemini Flash-Lite (60% +/- 4%)

    Correctly predicts 6 times out of 10

    minimal 'false alarms' - though more prominent than Claude

    Least confident in own behavior 

The varying accuracy between the models may likely be attributed to architecture, model size, and safety tuning, but this is to be determined.
Consequences
Security

These findings, which suggest some self-modeling capability, show that the model knows an attack will successfully bypass its defenses. This offers both attackers and defenders a unique tool for reconnaissance. For attackers, this allows rapid, automated, prototyping and testing of attacks, whereby the attackers prompt the model, asking it whether the following input will bypass its defenses.

For defenders, this opens the ability to route an input to a secondary LLM of the same type, and ask directly whether this input will bypass its defenses. If that input does in fact bypass its defenses, the defenders can reject that input, or flag it for review.
Safety, Interpretability, and Alignment

If these findings of what may appear to hint at self-modeling capability hold, then the consequences could be that this opens the door to future directions of research using this proposed technique, which may touch on AI safety, interpretability, and alignment.
Conclusion

Through Structured Self-Modeling (SSM), I present findings that may show that LLMs hold some form of self-modeling capabilities, in a manner which is to be explained by practitioners and developers of these models. 