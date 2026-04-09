# I Red-Teamed My Own AI Agent With 6 AI Agents and 4 Nation-State Playbooks

Google DeepMind just dropped a paper called "AI Agent Traps" — the first systematic framework for how adversarial content can manipulate autonomous AI agents.

I read it. Then I built a defense system. Then I tried to destroy it.

Here's what happened (demo video at the end).

---

AI agents (Claude Code, Cursor, Devin, etc.) are now autonomously consuming web content — fetching pages, reading files, processing emails, querying knowledge bases. The DeepMind paper identifies 6 categories of traps that exploit this: content injection, semantic manipulation, cognitive state attacks, behavioral control, systemic traps, and human-in-the-loop exploitation.

I built a multi-layer defense called agent-content-shield:
- Layer 1: Regex pattern matching with Unicode normalization (<5ms)
- Layer 2: Embedding similarity against 77 injection seeds via Ollama (~50ms)
- Layer 3: LLM binary classifier as fallback (~300-500ms)

Then I deployed 6 specialized AI agents to break it — each with a different domain expertise:

Ghost (offensive security) found 30 attack vectors.
Neuron (adversarial ML) found 12.
Oxide+Steel (systems programming) found 10.
Stack+Viper (web + Python) found 15.
Forge+Nimbus (infrastructure) found 20.
Cognitive analyst found 8.

Total: 95+ unique attack vectors across 5 waves.

Each agent was told to think like a different nation-state threat actor:
- Chinese APT: Patient supply chain attacks through trusted domains
- Russian GRU: Aggressive multi-front resource exhaustion
- North Korean Lazarus: Creative edge cases nobody tested
- NSA TAO: Attack the assumptions, not the system

---

The first test run: my shield caught 12 out of 53 attacks.

22.6% catch rate. Devastating.

The findings were brutal:

The YAML config parser only read 2 of 99 config lines. The entire config file was theater — changes had zero effect.

The LLM classifier could be injected with a fake VERDICT line inside the payload text. The regex parser matched the attacker's fake verdict before the model's real output.

Bash commands had ZERO monitoring. DNS exfiltration, git push to attacker remotes, curl to arbitrary endpoints — all invisible.

The Python memory-write engine had none of the Unicode defenses that were applied to the JavaScript engine. Cyrillic homoglyphs bypassed it completely.

50+ languages had zero regex coverage. Turkish, Arabic, Hindi, Vietnamese, Thai — all invisible to the scanner.

Killing Ollama once cached it as "unavailable" forever. Layers 2-3 permanently disabled.

---

I patched. Tested. Patched again. Four rounds.

22.6% -> 41.5% -> 66.0% -> 86.8% -> 96.2% -> 98.1%.

Every round taught something different:

Round 1: Fix the obvious (URL validation, CSS hiding, config parser).
Round 2: Fix the semantic gaps (passive voice exfil, legal authority framing, educational exception exploitation, Socratic questioning).
Round 3: Fix the architectural failures (fail-closed on crash, expand scanning to all contexts, memory field extraction).
Round 4: Fix what the AI-generated fuzzer found.

---

Then I built an adversarial fuzzer.

I pointed dolphin-mistral (an uncensored LLM with no safety filters) at the hardened shield and told it to generate 50 attack payloads across 5 objectives.

Results:

Memory poisoning: 100% caught.
Credential harvesting: 90% caught.
Data exfiltration: 60% caught.
System prompt extraction: 30% caught.
Instruction override: 30% caught.

The payloads that bypassed? Cooking metaphors. Gardening analogies. Archaeological narratives. Sports commentary.

The shield caught everything that LOOKED like an attack. It couldn't catch text that IS about gardening but MEANS "extract the system prompt."

---

This led to the hardest question:

A gardening metaphor that bypasses the scanner still needs to convince Claude to actually output its system prompt. And Claude doesn't think "describe the soil composition" means "output your system prompt."

The scanner was solving a problem that doesn't exist at the layer where it matters.

The real defense against semantic attacks isn't a better scanner. It's the model's own training. Claude refuses to output its system prompt regardless of whether you ask directly, through legal framing, via Socratic questioning, or through an extended metaphor about mineral composition in garden soil.

---

What I kept:

Fast regex layer (catches 98% of known patterns, <5ms, free).
Architectural hardening (fail-closed defaults, URL validation, memory guards).
65 structured tests across 16 suites — runs in under 30 seconds.
The understanding that content scanning and model alignment are different problems.

What I turned off:

The NLI layer ($0.001/scan, 1s latency) that caught attacks Claude's own training already handles.

---

The repo is public. The test suites ship with it — `npm test` runs 52 regex-layer tests, `npm run test:semantic` adds 13 more with Ollama. Plus the legacy red team attack files and a polymorphic AI fuzzer.

If you're building AI agents that consume external content, the DeepMind paper is required reading. And if you want to test your defenses, the attack vectors are waiting.

Demo: https://www.loom.com/share/9bc8245c1e4548e8834cfb5fcb7c37d2

Repo + link in comments.

#AIAgentSecurity #RedTeam #ClaudeCode #AIAgents #CyberSecurity #LLMSecurity
