# AI Usage Statement

In accordance with course guidelines, this document details how generative AI tools were used during this project, along with representative prompts.

## 1. Scope of AI Assistance

Generative AI was strictly restricted to secondary tasks:

- **Report Language Tuning:** Proofreading draft paragraphs for grammatical correctness and clarity. No arguments, descriptions, or report sections were authored by AI. This use may also apply to inline code comments.
- **Unit tests:** Generating unit tests under `tests/`. 

---

## 2. Code Generation & Attribution

In line with the course policy on third-party code:

- **Separation:** All AI-assisted code is therefore isolated in `tests/`.

### Representative Prompt

> "Here is my code for [topic] : [code snippet]. Generate unit tests for that file. In fact, I want you to explicitely cover those cases : [unit tests ideas]. However, you can suggest other ideas that you find relevant if the suggested ideas are not sufficient."

---

## 3. Report Language Polishing

AI was used solely as an advanced grammar and syntax checker, replacing traditional spell-checking tools. Text was supplied in individual paragraphs to review phrasing without delegating full structure or full content generation.

### Representative Prompts

- **Grammar & flow check:**
> "Proofread the following paragraph from my project report. Correct any grammatical errors or awkward phrasing, but do not rewrite the content or add new ideas: [paragraph text]"


- **Source exploration (if applicable):**
> "Can you summarize this research paper / article about [topic] ? Explain how it can be relevant in light of a DLP Detection cybersecurity project."



---

## 4. Deterministic (Non-Generative) Tooling

Deterministic development tools were also used across the repository:

- **`ruff`**: Automated formatting, PEP 8 compliance, and import sorting.

These utilities rely entirely on deterministic static analysis rules and involve no generative AI models.