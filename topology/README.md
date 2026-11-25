# Validation network

The [`validation_network.png`](validation_network.png) diagram shows the enterprise-like Kathará topology used in the experiments. Its `kathara/lab.conf` defines 31 devices and 31 collision domains; `kathara/ADDRESSING.txt` describes their interfaces and addressing. The startup and configuration files establish the routing, filtering and service behavior used as the experimental baseline.

The laboratory includes external services, headquarters, branch and data-centre networks, perimeter and internal firewalls, a ModSecurity WAF, and two Squid proxies. The management nodes are represented by placeholders in the distributed topology. Device configurations and traffic outcomes observed during the validation are provided under `RQ1/` and `RQ2/`.
