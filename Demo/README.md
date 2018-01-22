# Passive OS Fingerprint

# Acknowledgement
This repository is an attachement to the paper "Passive OS Fingerprint Prototype Demonstration" presented at NOMS 2018 conference.

M. Lastovicka, and D. Filakovsky, “Passive OS Fingerprint Prototype Demonstration” in Network Operations and Management Symposium (NOMS), 2018 IEEE

### Requirements
- [Flowmon](https://www.flowmon.com/en)
- [Neo4J](https://neo4j.com/)
- [Apoc](https://github.com/neo4j-contrib/neo4j-apoc-procedures)
- [neo4j-driver](https://github.com/neo4j/neo4j-python-driver)
- [flowmon-rest-api](https://gitlab.ics.muni.cz/CSIRT-MU/flowmon-rest-client)

### Run
You only need to open _config.ini_ and fill your login, host, profile from flowmon etc. and run _./run.py_

### Notes
You also need to add this line into _neo4j.conf_

    apoc.import.file.enabled=true

Set your monitored IP address range to src net and if you are limited by rest output limit (10.000 flows), you can filter traffic to accept only HTTP and HTTPS communication which mostly contains data about OS

