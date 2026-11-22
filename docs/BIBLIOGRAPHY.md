# ARGUS — Mathematical Foundations and Sources

**Read this first.** I produced the formal machinery in the ARGUS design from background knowledge, not by consulting papers as I wrote. Fabricated citations are a known LLM failure mode and would be serious in a thesis. So:

- **§1 — verified.** I searched for these during this session and confirmed authors, title, venue, year, and pages.
- **§2 — unverified.** High confidence these exist and are correctly attributed, but details (year, venue, page numbers) may be wrong. **Verify each before citing.**
- **§3 — the gap that matters most.** What I have *not* done, and what only you can do.

---

## 1. Verified sources

### Trust and uncertainty — `trust/subjective_logic.py`

Grounds: opinions ω = ⟨b, d, u, a⟩, the discount operator, fusion operators, and the ⟨b,d,u⟩ representation that lets "the sensor was blind" be expressed as uncertainty mass rather than disbelief.

> Jøsang, A. (2001). **A Logic for Uncertain Probabilities.** *International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems*, 9(3), 279–311.
> [worldscientific.com](https://www.worldscientific.com/doi/abs/10.1142/S0218488501000831) · [author PDF](https://www.mn.uio.no/ifi/english/people/aca/josang/publications/jos2001-ijufks.pdf)

This is the paper that makes the design's central distinction expressible. In plain probability, "no evidence" and "evidence against" both push toward low probability. Subjective logic separates disbelief `d` from uncertainty `u` — which is exactly the A04 case: Zeek's silence should raise `u`, not `d`. Note also that subjective logic draws on Dempster–Shafer belief theory, which is the natural alternative formalism if you decide against it.

### Argumentation — `argue/`, `decide/semantics.py`

Grounds: the argument graph, attack relations, and extension semantics (grounded = skeptical, preferred = credulous) that give `needs_review` a formal meaning.

> Dung, P. M. (1995). **On the acceptability of arguments and its fundamental role in nonmonotonic reasoning, logic programming and n-person games.** *Artificial Intelligence*, 77(2), 321–357.
> [ACM DL](https://dl.acm.org/doi/10.1016/0004-3702%2894%2900041-X)

The foundational paper. Arguments as nodes, attacks as edges, and the extension semantics ARGUS reads its verdict from.

> Modgil, S., & Prakken, H. (2014). **The ASPIC+ framework for structured argumentation: a tutorial.** *Argument & Computation*, 5(1), 31–62.
> [Taylor & Francis](https://www.tandfonline.com/doi/abs/10.1080/19462166.2013.869766) · [Utrecht repository](https://dspace.library.uu.nl/handle/1874/304259)

**The single most important reference for ARGUS.** ASPIC+ distinguishes strict from defeasible inference rules and — critically — defines exactly three ways an argument can be attacked: *on its uncertain premises, on its defeasible inferences, or on its conclusions.* That is precisely the **undermine / undercut / rebut** typology I specified. Do not reinvent this vocabulary; adopt it and cite it. It also gives you the preference machinery for resolving conflicts, which is where trust weights attach.

### Diagnosis under incomplete observation — `trust/observability.py`, `deliver/mvfes.py`

Grounds: reasoning from a system model plus partial observations, and the minimal-set computations behind both the minimal sufficient evidence set and MVFES.

> Reiter, R. (1987). **A theory of diagnosis from first principles.** *Artificial Intelligence*, 32(1), 57–95.
> [ACM DL](https://dl.acm.org/doi/10.1016/0004-3702(87)90062-2) · [PDF](https://cse.sc.edu/~mgv/csce580f11/gradPres/reiter-diagnosis.pdf)

The nearest prior art to C1, and you should engage with it directly rather than hope a reviewer misses it. Reiter's diagnoses are **minimal hitting sets of conflict sets**, computed via a hitting-set tree. Your **MVFES** is structurally the same computation over the argument graph, and framing it that way is a strength — it inherits fifty years of algorithms. It also sharpens your novelty claim: Reiter assumes a known system model and complete observations of what *was* observed; ARGUS adds a probabilistic account of *what could have been observed at all*, plus an adversary who controls part of the observation.

### Probabilistic logic and abduction — `decide/problog_model.py`

Grounds: `P(H)` and the abductive query behind value-of-information ranking.

> De Raedt, L., Kimmig, A., & Toivonen, H. (2007). **ProbLog: A probabilistic Prolog and its application in link discovery.** *IJCAI 2007*, 2462–2467.
> [IJCAI](https://www.ijcai.org/Abstract/07/396) · [ProbLog publications](https://dtai.cs.kuleuven.be/problog/publications.html)

Probabilistic facts, success probability of a query, BDD-based inference. The KU Leuven publications page is the place to find the current ProbLog2 papers, which is what you would actually implement against.

### Conformal prediction under shift — `decide/conformal.py`

Grounds: the fix for shortcoming S4 — SOC data is not exchangeable, so static split conformal guarantees do not hold.

> Gibbs, I., & Candès, E. J. (2021). **Adaptive Conformal Inference Under Distribution Shift.** *NeurIPS 34*, 1660–1672.
> [NeurIPS proceedings](https://proceedings.neurips.cc/paper/2021/hash/0d441de75945e5acbc865406fc9a2559-Abstract.html) · [arXiv 2106.00170](https://arxiv.org/pdf/2106.00170)

ACI re-estimates a single shift parameter online and wraps any black-box predictor. This is the method that rescues C3 from being a plain application of a known technique.

### Temporal reasoning — `resolve/temporal.py`

Grounds: interval-valued timestamps with skew bounds; "failed before success" as a relation that survives clock drift.

> Allen, J. F. (1983). **Maintaining knowledge about temporal intervals.** *Communications of the ACM*, 26(11), 832–843.
> [ACM DL](https://dl.acm.org/doi/10.1145/182.358434) · [CACM](https://cacm.acm.org/research/maintaining-knowledge-about-temporal-intervals/)

The thirteen interval relations and the composition table. You want the probabilistic extension of this, since your interval bounds are uncertain.

### Adversarial LLM input — `assurance/redteam/`

Grounds: the C4 threat model — logs are attacker-influenceable and an LLM reads them.

> Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). **Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection.** *AISec '23* (16th ACM Workshop on AI and Security).
> [arXiv 2302.12173](https://arxiv.org/abs/2302.12173) · [ACM DL](https://dl.acm.org/doi/abs/10.1145/3605764.3623985)

The canonical indirect-prompt-injection paper and their taxonomy. Your contribution is the security-telemetry setting specifically, where attacker control is *partial and structured* (the L0–L3 lattice) rather than total — which is a genuinely different threat surface from a web page or an email.

---

## 2. Unverified — check before citing

I did not search for these. Confidence is high that each exists and is correctly attributed, but **treat every detail as suspect** until you confirm it.

| Used for | Reference (unverified) |
|---|---|
| Beta reputation, sensor trust posteriors | Jøsang & Ismail, *The Beta Reputation System*, Bled eConference, 2002 |
| Subjective logic reference text | Jøsang, *Subjective Logic: A Formalism for Reasoning Under Uncertainty*, Springer, 2016 |
| Belief functions (alternative to §1 subjective logic) | Shafer, *A Mathematical Theory of Evidence*, Princeton, 1976 |
| Dependent-evidence critique — **directly relevant to your `confidence: 1.0` bug** | Zadeh's critique of Dempster's combination rule, ~1979/1986 |
| Conformal prediction foundations | Vovk, Gammerman & Shafer, *Algorithmic Learning in a Random World*, Springer, 2005 |
| Conformal tutorial (best entry point) | Angelopoulos & Bates, *A Gentle Introduction to Conformal Prediction…*, arXiv, 2021 |
| Conformal under covariate shift | Tibshirani, Barber, Candès & Ramdas, NeurIPS 2019 |
| Conformal without exchangeability | Barber, Candès, Ramdas & Tibshirani, *Conformal prediction beyond exchangeability*, Annals of Statistics, ~2023 |
| Abstention / reject option — the classical result | Chow, *On optimum recognition error and reject tradeoff*, IEEE Trans. Inf. Theory, 1970 |
| Selective classification | El-Yaniv & Wiener, JMLR 2010; Geifman & El-Yaniv, NeurIPS 2017 |
| Multiple-fault diagnosis, ATMS | de Kleer & Williams, *Diagnosing Multiple Faults*, AI, 1987 |
| Attacks on attacks — relevant to hypothesis-conditional trust | Modgil, *Reasoning about preferences in argumentation frameworks*, AI, 2009 |
| Bipolar argumentation (support + attack) | Cayrol & Lagasquie-Schiex, ~2005 |
| Rationality postulates for structured argumentation | Caminada & Amgoud, AI, ~2007 |
| Probabilistic argumentation | Li, Oren & Norman, TAFA 2011; Thimm, ECAI 2012; Hunter, IJAR 2013 |
| Value of information | Howard, *Information Value Theory*, IEEE Trans. SSC, 1966; Lindley, 1956 |
| Probabilistic entity resolution | Fellegi & Sunter, *A Theory for Record Linkage*, JASA, 1969 |
| Belief revision under new evidence (streaming) | Alchourrón, Gärdenfors & Makinson (AGM), JSL, 1985 |
| Minimal unsatisfiable subsets — MVFES algorithms | Liffiton & Sakallah, *Algorithms for computing minimal unsatisfiable subsets*, JAR, 2008 |
| Certified robustness framing | Cohen, Rosenfeld & Kolter, *Randomized Smoothing*, ICML 2019 |
| Markov logic (alternative to ProbLog) | Richardson & Domingos, *Markov Logic Networks*, Machine Learning, 2006 |
| Distribution semantics for probabilistic logic | Sato, ICLP 1995 |
| ATT&CK grounding | Strom et al., *MITRE ATT&CK: Design and Philosophy*, MITRE technical report |

**Not papers** — cite as tools/standards, not literature: DeTT&CT (Rabobank CDC), Atomic Red Team (Red Canary), OCSF, MITRE ATT&CK, Sigma.

---

## 3. What I have not done — and it is the important part

Everything above tells you **where the machinery comes from**. None of it tells you whether ARGUS is *novel*.

The novelty ratings I gave (C2 > C4 > C1 > C3) were judgments from background knowledge, **not the result of a systematic literature search.** I did not search for whether someone has already:

- applied argumentation semantics to SOC triage or alert correlation
- modelled sensor coverage probabilistically for security detection
- made evidence trust conditional on the hypothesis being evaluated
- computed certified robustness for a defeasible or argumentation-based decision
- used conformal prediction to gate alert auto-closure

**Any one of those could already exist and would change a contribution's status.** This is the single largest unquantified risk in the whole plan — larger than the dataset size problem, because it is invisible until a reviewer names the paper you missed.

### The search you need to run

Queries, on Google Scholar, ACM DL, IEEE Xplore, DBLP, and arXiv:

```
argumentation + "intrusion detection" | "security operations" | "alert triage"
"defeasible reasoning" + cybersecurity
"sensor coverage" | "detection coverage" + probabilistic + ATT&CK
"missing evidence" | "absence of evidence" + intrusion detection
"conformal prediction" + "intrusion detection" | "alert triage"
"subjective logic" + cybersecurity | "trust" + "security event"
"prompt injection" + logs | SIEM | "security telemetry"
LLM + "SOC" + triage       (2023–2026 — this space is moving fast)
```

Then follow citation graphs both directions from the §1 papers — forward citations of Dung and of ASPIC+ into security venues are where a competing system would most likely be hiding.

Also check whether **DeTT&CT** or any detection-engineering work has already formalised coverage probabilistically. That is the nearest thing to C1 in the practitioner world, and a reviewer from industry will know it.

### Do this before Phase 1, not before Phase 0

Phase 0 is parsers and reproducibility — nothing in it depends on the novelty question, so start building now. But **finish the systematic review before you commit to Gate B**, because that is the point where you would otherwise spend a year on a contribution that already exists.

Budget two to three weeks. It is the cheapest insurance in the plan.

---

**Sources verified in this session:** [Jøsang 2001](https://www.worldscientific.com/doi/abs/10.1142/S0218488501000831) · [Dung 1995](https://dl.acm.org/doi/10.1016/0004-3702%2894%2900041-X) · [Modgil & Prakken 2014](https://www.tandfonline.com/doi/abs/10.1080/19462166.2013.869766) · [Reiter 1987](https://dl.acm.org/doi/10.1016/0004-3702(87)90062-2) · [De Raedt et al. 2007](https://www.ijcai.org/Abstract/07/396) · [Gibbs & Candès 2021](https://proceedings.neurips.cc/paper/2021/hash/0d441de75945e5acbc865406fc9a2559-Abstract.html) · [Allen 1983](https://dl.acm.org/doi/10.1145/182.358434) · [Greshake et al. 2023](https://arxiv.org/abs/2302.12173)
