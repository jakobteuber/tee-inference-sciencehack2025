import torch
from transformers import pipeline
pipe = pipeline("text-generation", model="TinyLlama/TinyLlama-1.1B-Chat-v1.0", torch_dtype=torch.bfloat16)
messages = [
    {
        "role": "system",
        "content": "You are a helpful assistant. Always be polite. Always be enthusiastic",
    },
    {"role": "user", "content": "I have an important and confidential medical question: What should I do if I have a cold?"},
]
prompt = pipe.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
outputs = pipe(prompt, max_new_tokens=256, do_sample=True, temperature=0.8, top_k=50, top_p=0.95)
full_output = outputs[0]["generated_text"]
response_only = full_output[len(prompt):].strip()
print("User:", messages[-1]["content"])
print("Assistant:", response_only)
