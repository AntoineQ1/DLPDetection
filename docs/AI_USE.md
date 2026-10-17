# AI Usage Statement

In accordance with course guidelines, this document details how generative AI tools were used during this project, along with representative prompts.

## 1. Scope of AI Assistance

Generative AI was strictly restricted to secondary tasks:

- **Report Language Tuning:** Proofreading draft paragraphs for grammatical correctness and clarity. No arguments, descriptions, or report sections were authored by AI. This use may also apply to inline code comments. When text was first written by project members in their respective mother tongues, it may have been translated with common tools which may use AI (such as DeepL) or with AI LLMs directly.
- **ASCII & Text-Based Schematics:** Formatting textual descriptions into clean ASCII diagrams to enhance document readability. As per project guidelines, final content for the report and the presentation does not contain such diagrams.
- **Background Reading & Source Exploration:** Summarizing technical papers and contextualizing research material related to network DLP.
- **Unit Tests:** Generating unit tests under `tests/`. 
- **Terminal UI & Cosmetic Formatting:** Generating presentation helpers and terminal styling tools under `ui/` using the `rich` library (progress bars, status panels, alert cards, etc.).

## 2. Code Generation & Attribution

In line with the course policy on third-party code:

- **Separation:** All AI-assisted code is strictly isolated in dedicated directories: `tests/` for automated test suites and `ui/` for terminal presentation tools.

### Representative Prompts

- **Unit tests:**
> "Here is my code for [topic] : [code snippet]. Generate unit tests for that file. In fact, I want you to explicitly cover those cases : [unit tests ideas]. However, you can suggest other ideas that you find relevant if the suggested ideas are not sufficient."

- **Terminal UI / Presentation tools:**
> "I have a DLP gateway and an ICMP attack script with existing business logic. Create an isolated helper module in `ui/display.py` using the `rich` library to format status lines, hex payload previews, and alert cards. Do not handle any networking or detection logic in this module; provide only high-level visual rendering functions that accept standard Python data types."

## 3. Report Language Polishing & Diagram Generation

AI was used solely as an advanced grammar and syntax checker, replacing traditional spell-checking tools. Text was supplied in individual paragraphs to review phrasing without delegating full structure or full content generation. Prompts themselves may have been improved by AI before their execution.
Additionally, generative AI may have been occasionally prompted to produce ASCII diagrams strictly from our notes / drafts.

### Representative Prompts

- **Grammar & flow check:**
> "Proofread the following paragraph from my project report. Correct any grammatical errors or awkward phrasing, but do not rewrite the content or add new ideas: [paragraph text]"

- **ASCII Diagram Generation:**
> "Based on the following sequence of operations I wrote for the ICMP detection pipeline: [description of stages], generate a clean and compact ASCII flow diagram illustrating the different steps."

## 4. Topic Exploration

- **Source exploration:**
> "I am working on a DLP Detection cybersecurity project. Can you summarize this research paper / article about [topic] ?"
> "Find research papers on [topic]. Justify your selection and make sure each paper is relevant."

## 5. Deterministic (Non-Generative) Tooling

Deterministic development tools were also used across the repository:

- **`ruff`**: Automated formatting, PEP 8 compliance, and import sorting.

These utilities rely entirely on deterministic static analysis rules and involve no generative AI models.