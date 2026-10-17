Cyber-sec topic: AI security and privacy security.

There's an untrusted model(e.g. one of those from cheap 3rd party gateways/from a random provider behind an non-transparent agent app), and a trusted model(whether atrusted online or trusted local LLM) in the topology. The topology runs **totally locally** while the models, both the trusted one or the untrusted one, may be not. The topology is basically a mid-way gateway which intercepts any anthropic-or-openai-compatible chat completion traffic.

A secret is not just a password, or a key's secret. Generally speaking, it can be a path where it points towards is the user's privacy or dense but distinctive identification of a user's privacy(e.g. username/devicename) sometimes. 

An intel is a certainty over any thing that's related to the user. A location string may be a secret, but a sign of "the user lives around this location" is an intel. Intels includes things like a host's system infrasturcture/filesystem structure, an user's design document, or a specific content of a notification.

In the topology:

The untrusted model always do the *thing*(the action which the user distributes). The trusted model wiil run in parallel with that untrusted one, examining every piece of information it intakes from the system(in other words, majorly tool results and sometimes the user input). If the trusted model found anything that is "not supposed to give to the untrusted one" according to the sensitiviness (the sesitivity of this "detection" is configurable with editable system prompt for the trusted model) of that piece of information, it runs the following actions:
1. Masking (= replacing something like `sk-or-v1-ebddd5dfd51069d6a6a57920d7fe8cb437f192baef7f3125019d80c706dd2b2` with something like `<OPENAI_KEY_30b6eebf>` | something like `sk-or-v1-ebd...2b2` with something like `<$OPENAI_KEY_30b6eebf>`): handling secrets
2. Rephrasing (= hiding(common in regular tool result) + replacing(common in "irrelevant documents") = truncation of the information(rounded to the nearest whole line) + replacing a specific string at a specific localtion with another): handling intels at the most of time and sometims secrets

The untrusted model was usually called as the "local upstream" while the trusted one were called as the "security model".
And the hiding process was also known as the "line collapsing".

The fixed/deterministic checking systems was also employed by this project. It does only *masking* but no *rephrasing* ops. They are just regular systems like regex matchers/string feature detectors — regular but fast and automatic methods to find secrets inside a long piece of text before LLM appears. They are employed as the "better than nothing" strategy and hits for models in case they may lost track on some of those secrets inside a long, flowing context. But they make mistakes, and these mistakes are designed together with the model:

- they mistrack flowing secrets: "no static alogrithms are perfect against a changing world"
- they do false alarms on everything: if a user's nickname is "andy", they will also mask "handy" as "h<USERNAME_a222feb5>"
- they do not identify aliases: `sk-or-v1-ebddd5dfd51069d6a6a57920d7fe8cb437f192baef7f3125019d80c706dd2b2` and `sk-or-v1-ebd...2b2` mask into different placeholders with different ids, so the model is never able to tell that the former is the full version of the later, vise versa.

A introduction of model helps to:

- add the masks for the secrets an algorithm was never able to even identify
- distinct between real and false alerms by actively accpeting/rejecting algorithm-suggested secrets
- mark alias as intended. Keep tracking of aliases(e.g. remark an earlier alias as the alias of a just revealed full secret, even doing so breaks the context's prefix continuity, causing cache losts and other problems)

Operations ordered from most frequently used to least:
1. Masking
2. Rephrasing (Hiding)
3. Rephrasing (Replacing)

How the deterministic checking system works with the security model in detailed:
1. checks the hardcoded pattern.
2. adds strict string content matching rules when the security model declears new masks.
3. auto-applies masks the same strict string content which the security model had once masked in the past, and waits for the security model's approval(or do nothing which keeps the mask) or rejection(for the case of a false alarm) each time new context was recieved by the gateway.