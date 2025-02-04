# CAPoW: Context-Aware AI-Assisted Proof of Work based DDoS Defense
Critical servers can be secured against distributed denial of service (DDoS) attacks using proof of work (PoW) systems assisted by an Artificial Intelligence (AI) that learns contextual network request patterns. In this work, we introduce CAPoW, a context-aware anti-DDoS framework that injects latency adaptively during communication by utilizing context-aware PoW puzzles. In CAPoW, a security professional can define relevant request context attributes which can be learned by the AI system. These contextual attributes can include information about the user request, such as IP address, time, flow-level information, etc., and are utilized to generate a contextual score for incoming requests that influence the hardness of a PoW puzzle. These puzzles need to be solved by a user before the server begins to process their request. Solving puzzles slows down the volume of incoming adversarial requests. Additionally, the framework compels the adversary to incur a cost per request, hence making it expensive for an adversary to prolong a DDoS attack. We include the theoretical foundations of the CAPoW framework along with a description of its implementation and evaluation.


Please cite the following paper if you use the materials.
```
@article{chakraborty2023capow,
  title={Capow: Context-aware ai-assisted proof of work based ddos defense},
  author={Chakraborty, Trisha and Mitra, Shaswata and Mittal, Sudip},
  journal={arXiv preprint arXiv:2301.11767},
  year={2023}
}
```
