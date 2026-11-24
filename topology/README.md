# Kathará validation topology

The supplied `kathara/` directory contains the reference network model and baseline security configurations.
Its `lab.conf` defines **31 nodes and 31 collision domains**, including external test hosts, perimeter and internal firewalls, two core routers, a branch WAN, headquarters and branch proxies, a web application firewall, and management nodes.
`ADDRESSING.txt` documents the interfaces and addressing; `validation_network.png` illustrates the intended network arrangement.

The public laboratory retains the data-plane nodes and the reference service images built by `images/build-images.sh`.
The two control-plane service images (`refinement_engine` and `capability_catalogue`) have been replaced with base-image placeholders at the same modelled network addresses.
Their proprietary application services are not provided.
The distributed configuration therefore permits examination of the topology and baseline networking without implying that the full refinement/deployment pipeline can run independently.

The included host-side rule installation, removal and baseline check utilities are Kathará-laboratory support tools; they are not RefinementEngine application source code.
Review rules and addresses before execution and use only an isolated laboratory.
Do not apply recorded sample restrictions to production systems or public endpoints.

To inspect the layout without starting containers, read `kathara/lab.conf` and `kathara/ADDRESSING.txt`.
For a baseline environment, install Kathará and Docker, build the image definitions under `kathara/images/`, and follow the device start-up configuration.
Full CTI-to-rule evaluation requires the separately maintained RefinementEngine implementation.
